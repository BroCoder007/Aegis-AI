use notify::{EventKind, RecursiveMode, Watcher};
use serde::Serialize;
use std::{
    collections::VecDeque,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};
#[derive(Clone, Serialize, Default)]
pub struct Status {
    pub running: bool,
    pub roots: Vec<String>,
    pub checked: usize,
    pub dropped: usize,
    pub events: VecDeque<String>,
}
pub struct Monitor {
    pub stop: Arc<AtomicBool>,
    pub status: Arc<Mutex<Status>>,
}
pub fn start(
    roots: Vec<String>,
    engine: Option<crate::engine::EngineConfig>,
) -> Result<Monitor, String> {
    if roots.is_empty() || roots.len() > 8 {
        return Err("Select 1–8 folders".into());
    }
    let roots: Vec<PathBuf> = roots
        .iter()
        .map(|r| std::fs::canonicalize(r).map_err(|e| e.to_string()))
        .collect::<Result<_, _>>()?;
    if roots.iter().any(|r| !r.is_dir()) {
        return Err("Monitoring requires directories".into());
    }
    let (status, stop) = (
        Arc::new(Mutex::new(Status {
            running: true,
            roots: roots.iter().map(|p| p.display().to_string()).collect(),
            ..Default::default()
        })),
        Arc::new(AtomicBool::new(false)),
    );
    let (tx, rx) = std::sync::mpsc::sync_channel(256);
    let dropped = Arc::new(AtomicUsize::new(0));
    let d = dropped.clone();
    let mut watcher = notify::recommended_watcher(move |event: notify::Result<notify::Event>| {
        if tx.try_send(event).is_err() {
            d.fetch_add(1, Ordering::Relaxed);
        }
    })
    .map_err(|e| e.to_string())?;
    for root in &roots {
        watcher
            .watch(root, RecursiveMode::Recursive)
            .map_err(|e| e.to_string())?;
    }
    let s = status.clone();
    let c = stop.clone();
    std::thread::spawn(move || {
        let _watcher = watcher;
        let mut recent = std::collections::HashMap::<PathBuf, std::time::Instant>::new();
        while !c.load(Ordering::Relaxed) {
            s.lock().unwrap().dropped = dropped.load(Ordering::Relaxed);
            match rx.recv_timeout(Duration::from_millis(500)) {
                Ok(Ok(event)) => {
                    if !matches!(event.kind, EventKind::Create(_) | EventKind::Modify(_)) {
                        continue;
                    }
                    for path in event.paths {
                        if c.load(Ordering::Relaxed) {
                            break;
                        }
                        if !eligible(&path, &roots) {
                            continue;
                        }
                        let now = std::time::Instant::now();
                        recent.retain(|_, t| now.duration_since(*t) < Duration::from_secs(2));
                        if recent.contains_key(&path) {
                            continue;
                        }
                        if recent.len() >= 256 {
                            recent.clear();
                        }
                        recent.insert(path.clone(), now);
                        let r = crate::scanner::inspect(&path, 128 * 1024 * 1024, &c);
                        let mut signature = if r.error.is_none() {
                            engine
                                .as_ref()
                                .map(|e| crate::engine::scan(e, &path, 128 * 1024 * 1024))
                        } else {
                            None
                        };
                        if let Some(v) = signature.as_mut() {
                            if v.sha256.is_some() && v.sha256 != r.sha256 {
                                v.status = "error".into();
                                v.detail = "File changed between static and signature scans".into();
                            }
                        }
                        let mut p = s.lock().unwrap();
                        p.checked += 1;
                        let detail = if let Some(error) = r.error {
                            format!("not assessed: {error}")
                        } else if let Some(v) = signature {
                            format!("{}: {}", v.status, v.detail)
                        } else {
                            format!(
                                "{} static indicators; no signature engine",
                                r.findings.len()
                            )
                        };
                        p.events
                            .push_front(format!("{} — {detail}", path.display()));
                        p.events.truncate(100);
                    }
                }
                Ok(Err(e)) => {
                    let mut p = s.lock().unwrap();
                    p.events.push_front(format!("Watcher error: {e}"));
                    p.events.truncate(100);
                }
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
                Err(_) => {}
            }
        }
        s.lock().unwrap().running = false;
    });
    Ok(Monitor { stop, status })
}
fn eligible(path: &Path, roots: &[PathBuf]) -> bool {
    let Ok(meta) = std::fs::symlink_metadata(path) else {
        return false;
    };
    if !meta.is_file() || meta.file_type().is_symlink() {
        return false;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if meta.file_attributes() & 0x400 != 0 {
            return false;
        }
    }
    let Ok(path) = path.canonicalize() else {
        return false;
    };
    roots.iter().any(|r| path.starts_with(r))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn out_of_scope_is_rejected() {
        let dir = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
        std::fs::create_dir(&dir).unwrap();
        let file = dir.join("fixture");
        std::fs::write(&file, b"test").unwrap();
        assert!(eligible(&file, &[dir.canonicalize().unwrap()]));
        assert!(!eligible(&file, &[dir.join("other")]));
        std::fs::remove_dir_all(dir).unwrap();
    }
}

#[cfg(test)]
mod live_tests {
    use super::*;
    #[test]
    fn receives_created_file() {
        let dir = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
        std::fs::create_dir(&dir).unwrap();
        let monitor = start(vec![dir.display().to_string()], None).unwrap();
        std::fs::write(dir.join("fixture.txt"), b"benign").unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(8);
        while monitor.status.lock().unwrap().checked == 0 && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(100));
        }
        let checked = monitor.status.lock().unwrap().checked;
        monitor.stop.store(true, Ordering::Relaxed);
        while monitor.status.lock().unwrap().running && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(100));
        }
        assert!(checked > 0);
        assert!(!monitor.status.lock().unwrap().running);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
