pub mod ai_pipeline;
pub mod orchestrator;
pub mod validator;
pub mod threat_intel;
pub mod database;

use tokio::sync::Mutex;
use std::collections::HashMap;
use std::sync::Arc;
use tauri::{State, Manager, AppHandle};

// Background state holding our scans
pub struct AppState {
    pub scans: Arc<Mutex<HashMap<String, Option<Result<ai_pipeline::ThreatAnalysisReport, String>>>>>,
}

#[tauri::command]
async fn start_scan(
    file_path: String,
    state: State<'_, AppState>,
    app_handle: AppHandle,
) -> Result<String, String> {
    let scan_id = uuid::Uuid::new_v4().to_string();
    
    {
        let mut scans = state.scans.lock().await;
        scans.insert(scan_id.clone(), None);
    }

    let scans_clone = state.scans.clone();
    let scan_id_clone = scan_id.clone();
    let file_path_clone = file_path.clone();
    
    tokio::spawn(async move {
        let telemetry = orchestrator::simulate_sandbox_execution(&file_path_clone).await;
        
        let vt_report = threat_intel::check_hash(&telemetry.sha256_hash).await;
        
        let mut scans = scans_clone.lock().await;
        match ai_pipeline::evaluate_telemetry(&telemetry, vt_report).await {
            Ok(report) => {
                // Log seamlessly to SQLite
                let _ = database::insert_scan(&app_handle, &scan_id_clone, &file_path_clone, report.risk_score, &report.threat_categories);
                scans.insert(scan_id_clone, Some(Ok(report)));
            }
            Err(e) => {
                // Log and save the error state
                log::error!("Pipeline Error: {}", e);
                scans.insert(scan_id_clone, Some(Err(e)));
            }
        }
    });

    Ok(scan_id)
}

#[tauri::command]
async fn get_scan_status(
    scan_id: String,
    state: State<'_, AppState>,
) -> Result<Option<ai_pipeline::ThreatAnalysisReport>, String> {
    let scans = state.scans.lock().await;
    if let Some(report_opt) = scans.get(&scan_id) {
        if let Some(res) = report_opt {
             match res {
                 Ok(report) => return Ok(Some(ai_pipeline::ThreatAnalysisReport {
                     risk_score: report.risk_score,
                     threat_categories: report.threat_categories.clone(),
                     plain_english_explanation: report.plain_english_explanation.clone(),
                     bouncer_yara: report.bouncer_yara.clone(),
                     bouncer_behavioral: report.bouncer_behavioral.clone(),
                 })),
                 Err(e) => return Err(e.clone()),
             }
        }
        Ok(None) // Still scanning
    } else {
        Err("Scan ID not found".to_string())
    }
}

#[tauri::command]
async fn get_scan_history(app_handle: AppHandle) -> Result<Vec<database::ScanHistoryItem>, String> {
    database::fetch_history(&app_handle).map_err(|e| format!("DB Fetch Error: {}", e))
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .setup(|app| {
            let _ = database::initialize_database(app.handle());
            Ok(())
        })
        .manage(AppState {
            scans: Arc::new(Mutex::new(HashMap::new())),
        })
        .plugin(tauri_plugin_log::Builder::default().build())
        .invoke_handler(tauri::generate_handler![
            start_scan,
            get_scan_status,
            get_scan_history
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
