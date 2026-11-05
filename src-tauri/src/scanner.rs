use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File},
    io::Read,
    path::Path,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
};
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct FileReport {
    pub path: String,
    pub sha256: Option<String>,
    pub bytes: u64,
    pub findings: Vec<String>,
    pub error: Option<String>,
}
#[derive(Clone, Serialize, Default)]
pub struct Progress {
    pub id: String,
    pub targets: Vec<String>,
    pub max_files: usize,
    pub max_bytes: u64,
    pub started_unix_seconds: u64,
    pub state: String,
    pub inspected: usize,
    pub skipped: usize,
    pub entries: usize,
    pub results: Vec<FileReport>,
    pub errors: Vec<String>,
    pub ai: Option<String>,
    pub report_path: Option<String>,
}
pub type Shared = Arc<Mutex<Progress>>;
pub fn inspect(path: &Path, limit: u64, cancel: &AtomicBool) -> FileReport {
    let mut report = FileReport {
        path: path.display().to_string(),
        sha256: None,
        bytes: 0,
        findings: vec![],
        error: None,
    };
    let result = (|| -> Result<(), String> {
        let mut file = File::open(path).map_err(|e| e.to_string())?;
        let before = file.metadata().map_err(|e| e.to_string())?;
        if !before.is_file() {
            return Err("Not a regular file".into());
        }
        if before.len() > limit {
            return Err("File exceeds configured size limit; not scanned".into());
        }
        let mut hash = Sha256::new();
        let mut buf = [0u8; 65536];
        let mut preview = Vec::new();
        loop {
            if cancel.load(Ordering::Relaxed) {
                return Err("Cancelled during file read".into());
            }
            let n = file.read(&mut buf).map_err(|e| e.to_string())?;
            if n == 0 {
                break;
            }
            report.bytes += n as u64;
            if report.bytes > limit {
                return Err("File grew beyond scan limit".into());
            }
            hash.update(&buf[..n]);
            if preview.len() < 262144 {
                preview.extend_from_slice(&buf[..n.min(262144 - preview.len())]);
            }
        }
        let after = file.metadata().map_err(|e| e.to_string())?;
        if before.len() != after.len() || before.modified().ok() != after.modified().ok() {
            return Err("File changed while scanning; repeat scan".into());
        }
        report.sha256 = Some(hex::encode(hash.finalize()));
        let text = String::from_utf8_lossy(&preview).to_lowercase();
        for (pattern, description) in [
            ("-encodedcommand", "Encoded PowerShell command reference"),
            ("downloadstring(", "Script download-and-evaluate primitive"),
            ("createremotethread", "Remote-thread API reference"),
            (
                "vssadmin delete shadows",
                "Shadow-copy deletion command reference",
            ),
        ] {
            if text.contains(pattern) {
                report.findings.push(description.into());
            }
        }
        let name = path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_lowercase();
        if [".pdf.exe", ".jpg.exe", ".docx.exe"]
            .iter()
            .any(|x| name.ends_with(x))
        {
            report
                .findings
                .push("Executable uses a document-like double extension".into());
        }
        if preview.starts_with(b"MZ")
            && path.extension().map(|e| e.to_string_lossy().to_lowercase()) != Some("exe".into())
            && path.extension().map(|e| e.to_string_lossy().to_lowercase()) != Some("dll".into())
        {
            report
                .findings
                .push("DOS/PE-style header with a nonstandard extension; inspect context".into());
        }
        Ok(())
    })();
    if let Err(e) = result {
        report.error = Some(e);
    }
    report
}
fn skip_link(meta: &fs::Metadata) -> bool {
    if meta.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if meta.file_attributes() & 0x400 != 0 {
            return true;
        }
    }
    false
}
pub fn scan(
    roots: Vec<String>,
    max_files: usize,
    max_bytes: u64,
    progress: Shared,
    cancel: Arc<AtomicBool>,
) {
    let mut stack: Vec<_> = roots.into_iter().map(std::path::PathBuf::from).collect();
    let mut seen = std::collections::HashSet::new();
    while let Some(path) = stack.pop() {
        if cancel.load(Ordering::Relaxed) {
            progress.lock().unwrap().state = "cancelled".into();
            return;
        }
        {
            let mut p = progress.lock().unwrap();
            if p.inspected >= max_files || p.entries >= max_files.saturating_mul(10) {
                p.state = "limited".into();
                return;
            }
            p.entries += 1;
        }
        let meta = match fs::symlink_metadata(&path) {
            Ok(m) => m,
            Err(e) => {
                let mut p = progress.lock().unwrap();
                p.skipped += 1;
                if p.errors.len() < 100 {
                    p.errors.push(format!("{}: {e}", path.display()));
                }
                continue;
            }
        };
        if skip_link(&meta) {
            progress.lock().unwrap().skipped += 1;
            continue;
        }
        if !seen.insert(path.clone()) {
            continue;
        }
        if meta.is_dir() {
            match fs::read_dir(&path) {
                Ok(entries) => {
                    for entry in entries {
                        if stack.len() >= max_files.saturating_mul(10) {
                            progress.lock().unwrap().state = "limited".into();
                            return;
                        }
                        match entry {
                            Ok(e) => stack.push(e.path()),
                            Err(e) => {
                                let mut p = progress.lock().unwrap();
                                p.skipped += 1;
                                if p.errors.len() < 100 {
                                    p.errors.push(e.to_string());
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    let mut p = progress.lock().unwrap();
                    p.skipped += 1;
                    if p.errors.len() < 100 {
                        p.errors.push(format!("{}: {e}", path.display()));
                    }
                }
            }
        } else if meta.is_file() {
            let r = inspect(&path, max_bytes, &cancel);
            let mut p = progress.lock().unwrap();
            p.inspected += 1;
            if r.error.is_some() {
                p.skipped += 1;
            }
            p.results.push(r);
        }
    }
    progress.lock().unwrap().state = "completed".into();
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn real_file_hash_and_size_limit() {
        let path = std::env::temp_dir().join(format!("aegis-{}.txt", uuid::Uuid::new_v4()));
        fs::write(&path, b"hello").unwrap();
        let r = inspect(&path, 100, &AtomicBool::new(false));
        assert_eq!(
            r.sha256.unwrap(),
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
        assert!(inspect(&path, 1, &AtomicBool::new(false)).error.is_some());
        fs::remove_file(path).unwrap();
    }
    #[test]
    fn cancel_and_missing_are_not_clean() {
        assert!(inspect(
            Path::new("__missing_aegis_file__"),
            100,
            &AtomicBool::new(false)
        )
        .error
        .is_some());
    }
}

#[cfg(test)]
mod traversal_tests {
    use super::*;
    #[test]
    fn folders_are_real_and_limits_are_visible() {
        let root = std::env::temp_dir().join(format!("aegis-folder-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(root.join("nested")).unwrap();
        fs::write(root.join("a.txt"), b"hello").unwrap();
        fs::write(root.join("nested/b.ps1"), b"powershell -EncodedCommand abc").unwrap();
        let p = Arc::new(Mutex::new(Progress::default()));
        scan(
            vec![root.display().to_string()],
            10,
            1024,
            p.clone(),
            Arc::new(AtomicBool::new(false)),
        );
        let r = p.lock().unwrap();
        assert_eq!(r.state, "completed");
        assert_eq!(r.inspected, 2);
        assert!(r.results.iter().any(|f| !f.findings.is_empty()));
        drop(r);
        let p = Arc::new(Mutex::new(Progress::default()));
        scan(
            vec![root.display().to_string()],
            1,
            1024,
            p.clone(),
            Arc::new(AtomicBool::new(false)),
        );
        assert_eq!(p.lock().unwrap().state, "limited");
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn pre_cancelled_scan_does_not_read_files() {
        let p = Arc::new(Mutex::new(Progress::default()));
        scan(
            vec!["missing".into()],
            10,
            1024,
            p.clone(),
            Arc::new(AtomicBool::new(true)),
        );
        assert_eq!(p.lock().unwrap().state, "cancelled");
        assert_eq!(p.lock().unwrap().inspected, 0);
    }
}
