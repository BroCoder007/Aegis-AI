mod engine;
mod models;
mod monitor;
mod quarantine;
mod scanner;
use scanner::{Progress, Shared};
use serde::Serialize;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use tauri::{Manager, State};
struct Job {
    progress: Shared,
    cancel: Arc<AtomicBool>,
}
#[derive(Default)]
struct AppState {
    job: Mutex<Option<Job>>,
    monitor: Mutex<Option<monitor::Monitor>>,
}
#[tauri::command]
async fn pick_target(folder: bool) -> Result<Option<String>, String> {
    tokio::task::spawn_blocking(move || {
        let dialog = rfd::FileDialog::new();
        if folder {
            dialog.pick_folder()
        } else {
            dialog.pick_file()
        }
        .map(|p| p.display().to_string())
    })
    .await
    .map_err(|e| e.to_string())
}
#[tauri::command]
fn computer_roots() -> Vec<String> {
    sysinfo::Disks::new_with_refreshed_list()
        .iter()
        .map(|d| d.mount_point().display().to_string())
        .collect()
}
#[tauri::command]
async fn list_models(config: models::ModelConfig) -> Result<Vec<String>, String> {
    models::list(config).await
}
#[tauri::command]
fn start_scan(
    roots: Vec<String>,
    max_files: usize,
    max_mb: u64,
    ai: Option<models::ModelConfig>,
    engine: Option<engine::EngineConfig>,
    state: State<'_, AppState>,
    app: tauri::AppHandle,
) -> Result<String, String> {
    if roots.is_empty()
        || roots.len() > 32
        || max_files == 0
        || max_files > 50000
        || max_mb == 0
        || max_mb > 1024
    {
        return Err("Select 1–32 targets, 1–50000 files and 1–1024 MiB per file".into());
    }
    for root in &roots {
        if !std::path::Path::new(root).is_absolute() {
            return Err("Targets must be absolute paths".into());
        }
    }
    let mut slot = state.job.lock().map_err(|e| e.to_string())?;
    if let Some(j) = slot.as_ref() {
        if matches!(
            j.progress.lock().unwrap().state.as_str(),
            "scanning" | "ai_analysis"
        ) {
            return Err("A scan is already running".into());
        }
    }
    let id = uuid::Uuid::new_v4().to_string();
    let progress = Arc::new(Mutex::new(Progress {
        id: id.clone(),
        targets: roots.clone(),
        max_files,
        max_bytes: max_mb * 1024 * 1024,
        started_unix_seconds: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        state: "scanning".into(),
        ..Default::default()
    }));
    let cancel = Arc::new(AtomicBool::new(false));
    *slot = Some(Job {
        progress: progress.clone(),
        cancel: cancel.clone(),
    });
    tauri::async_runtime::spawn(async move {
        let p = progress.clone();
        let c = cancel.clone();
        if let Err(e) = tokio::task::spawn_blocking(move || {
            if let Some(config) = &engine {
                match engine::version(config) {
                    Ok(version) => p.lock().unwrap().engine_version = Some(version),
                    Err(error) => {
                        let mut snapshot = p.lock().unwrap();
                        snapshot.state = "failed".into();
                        snapshot.errors.push(format!(
                            "Signature engine unavailable; scan not started: {error}"
                        ));
                        return;
                    }
                }
            }
            scanner::scan_with_engine(roots, max_files, max_mb * 1024 * 1024, p, c, engine)
        })
        .await
        {
            let mut p = progress.lock().unwrap();
            p.state = "failed".into();
            p.errors.push(e.to_string());
        }
        if let Some(config) = ai {
            if !cancel.load(Ordering::Relaxed) && progress.lock().unwrap().state != "failed" {
                let (evidence, previous) = {
                    let mut p = progress.lock().unwrap();
                    let previous = p.state.clone();
                    let evidence=serde_json::json!({"state":p.state,"inspected":p.inspected,"skipped":p.skipped,"observations":p.results.iter().filter(|r|!r.findings.is_empty()).take(20).collect::<Vec<_>>()}).to_string();
                    p.state = "ai_analysis".into();
                    (evidence, previous)
                };
                let result = models::summarize(config, evidence).await;
                let mut p = progress.lock().unwrap();
                p.state = previous;
                match result {
                    Ok(text) => p.ai = Some(text),
                    Err(e) => p
                        .errors
                        .push(format!("AI unavailable; static results retained: {e}")),
                }
            }
        }
        if cancel.load(Ordering::Relaxed) {
            progress.lock().unwrap().state = "cancelled".into();
        }
        match app.path().app_local_data_dir() {
            Ok(mut dir) => {
                dir.push("reports");
                let saved = (|| -> Result<(), String> {
                    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
                    let mut p = progress.lock().unwrap();
                    dir.push(format!("{}.json", p.id));
                    p.report_path = Some(dir.display().to_string());
                    let file = std::fs::File::create(&dir).map_err(|e| e.to_string())?;
                    serde_json::to_writer_pretty(file, &*p).map_err(|e| e.to_string())?;
                    Ok(())
                })();
                if let Err(e) = saved {
                    progress
                        .lock()
                        .unwrap()
                        .errors
                        .push(format!("Report could not be saved: {e}"));
                }
            }
            Err(e) => progress
                .lock()
                .unwrap()
                .errors
                .push(format!("Report path unavailable: {e}")),
        }
    });
    Ok(id)
}
#[tauri::command]
fn cancel_scan(state: State<'_, AppState>) {
    if let Some(j) = state.job.lock().unwrap().as_ref() {
        j.cancel.store(true, Ordering::Relaxed);
    }
}
#[derive(Serialize)]
struct Snapshot {
    id: String,
    state: String,
    inspected: usize,
    skipped: usize,
    entries: usize,
    total: usize,
    results: Vec<scanner::FileReport>,
    errors: Vec<String>,
    ai: Option<String>,
    report_path: Option<String>,
}
#[tauri::command]
fn scan_status(offset: usize, state: State<'_, AppState>) -> Option<Snapshot> {
    let slot = state.job.lock().ok()?;
    let p = slot.as_ref()?.progress.lock().ok()?;
    Some(Snapshot {
        id: p.id.clone(),
        state: p.state.clone(),
        inspected: p.inspected,
        skipped: p.skipped,
        entries: p.entries,
        total: p.results.len(),
        results: p.results.iter().skip(offset).take(100).cloned().collect(),
        errors: p.errors.clone(),
        ai: p.ai.clone(),
        report_path: p.report_path.clone(),
    })
}
#[derive(Serialize)]
struct Health {
    total_memory: u64,
    available_memory: u64,
    suggestions: Vec<String>,
    disks: Vec<(String, u64, u64)>,
}
#[tauri::command]
async fn system_health() -> Result<Health, String> {
    tokio::task::spawn_blocking(||{let mut s=sysinfo::System::new();s.refresh_memory();let mut suggestions=vec!["Review startup apps in system settings; disable only items you recognize and do not need.".into(),"Install OS and browser updates, and keep your existing real-time antivirus enabled.".into(),"Check Task Manager or Activity Monitor for sustained resource usage before changing settings.".into()];if s.available_memory()<s.total_memory()/5{suggestions.push("Available memory is below 20%; consider closing unused applications before loading a large local model.".into());}let disks=sysinfo::Disks::new_with_refreshed_list().iter().map(|d|{if d.available_space()<d.total_space()/10{suggestions.push(format!("{} has under 10% free space; review storage settings and back up important files before deleting anything.",d.mount_point().display()));}(d.mount_point().display().to_string(),d.available_space(),d.total_space())}).collect();Health{total_memory:s.total_memory(),available_memory:s.available_memory(),suggestions,disks}}).await.map_err(|e|e.to_string())
}

fn vault(app: &tauri::AppHandle) -> Result<std::path::PathBuf, String> {
    Ok(app
        .path()
        .app_local_data_dir()
        .map_err(|e| e.to_string())?
        .join("quarantine"))
}
#[tauri::command]
async fn engine_status(config: engine::EngineConfig) -> Result<String, String> {
    tokio::task::spawn_blocking(move || engine::version(&config))
        .await
        .map_err(|e| e.to_string())?
}
#[tauri::command]
async fn quarantine_file(
    path: String,
    sha256: String,
    app: tauri::AppHandle,
) -> Result<quarantine::Entry, String> {
    let dir = vault(&app)?;
    tokio::task::spawn_blocking(move||{if rfd::MessageDialog::new().set_title("Quarantine this file?").set_description(format!("Move this file out of its original location and encrypt it? This may break software.\n\n{path}\n\nOnly proceed after reviewing the detection. No files are moved automatically.")).set_buttons(rfd::MessageButtons::YesNo).show()!=rfd::MessageDialogResult::Yes{return Err("Cancelled".into());}quarantine::put(&dir,std::path::Path::new(&path),&sha256)}).await.map_err(|e|e.to_string())?
}
#[tauri::command]
fn quarantine_list(app: tauri::AppHandle) -> Result<Vec<quarantine::Entry>, String> {
    quarantine::list(&vault(&app)?)
}
#[tauri::command]
async fn quarantine_restore(id: String, app: tauri::AppHandle) -> Result<String, String> {
    let dir = vault(&app)?;
    tokio::task::spawn_blocking(move||{if rfd::MessageDialog::new().set_title("Restore quarantined file?").set_description("The file may still be malicious. Restore only after verifying the finding. Existing files will not be overwritten.").set_buttons(rfd::MessageButtons::YesNo).show()!=rfd::MessageDialogResult::Yes{return Err("Cancelled".into());}quarantine::restore(&dir,&id)}).await.map_err(|e|e.to_string())?
}
#[tauri::command]
fn start_monitor(
    roots: Vec<String>,
    engine: Option<engine::EngineConfig>,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let mut slot = state.monitor.lock().map_err(|e| e.to_string())?;
    if slot
        .as_ref()
        .is_some_and(|m| m.status.lock().unwrap().running)
    {
        return Err("Stop the existing monitor first".into());
    }
    if let Some(config) = &engine {
        engine::version(config)
            .map_err(|e| format!("Signature engine unavailable; monitor not started: {e}"))?;
    }
    *slot = Some(monitor::start(roots, engine)?);
    Ok(())
}
#[tauri::command]
fn stop_monitor(state: State<'_, AppState>) {
    if let Some(m) = state.monitor.lock().unwrap().as_ref() {
        m.stop.store(true, Ordering::Relaxed);
    }
}
#[tauri::command]
fn monitor_status(state: State<'_, AppState>) -> monitor::Status {
    state
        .monitor
        .lock()
        .unwrap()
        .as_ref()
        .map(|m| m.status.lock().unwrap().clone())
        .unwrap_or_default()
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .manage(AppState::default())
        .invoke_handler(tauri::generate_handler![
            pick_target,
            computer_roots,
            list_models,
            start_scan,
            cancel_scan,
            scan_status,
            system_health,
            engine_status,
            quarantine_file,
            quarantine_list,
            quarantine_restore,
            start_monitor,
            stop_monitor,
            monitor_status
        ])
        .run(tauri::generate_context!())
        .expect("Failed to start Aegis AI");
}
