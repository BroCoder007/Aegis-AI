use rusqlite::{Connection, Result};
use tauri::Manager;
use serde::{Deserialize, Serialize};
use log;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ScanHistoryItem {
    pub scan_id: String,
    pub filename: String,
    pub risk_score: u8,
    pub threat_categories: String,
    pub timestamp: String,
}

pub fn get_db_path(app_handle: &tauri::AppHandle) -> std::path::PathBuf {
    let mut path = app_handle.path().app_local_data_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));
    std::fs::create_dir_all(&path).ok();
    path.push("aegis_scans.sqlite");
    path
}

pub fn initialize_database(app_handle: &tauri::AppHandle) -> Result<()> {
    let conn = Connection::open(get_db_path(app_handle))?;
    conn.execute(
        "CREATE TABLE IF NOT EXISTS scans (
            scan_id TEXT PRIMARY KEY,
            filename TEXT NOT NULL,
            risk_score INTEGER NOT NULL,
            threat_categories TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )",
        [],
    )?;
    Ok(())
}

pub fn insert_scan(app_handle: &tauri::AppHandle, scan_id: &str, filename: &str, risk_score: u8, threat_categories: &[String]) -> Result<()> {
    let conn = Connection::open(get_db_path(app_handle))?;
    let categories_str = threat_categories.join(", ");
    conn.execute(
        "INSERT INTO scans (scan_id, filename, risk_score, threat_categories) VALUES (?1, ?2, ?3, ?4)",
        [scan_id, filename, &risk_score.to_string(), &categories_str],
    )?;
    Ok(())
}

pub fn fetch_history(app_handle: &tauri::AppHandle) -> Result<Vec<ScanHistoryItem>> {
    let conn = Connection::open(get_db_path(app_handle))?;
    let mut stmt = conn.prepare("SELECT scan_id, filename, risk_score, threat_categories, timestamp FROM scans ORDER BY timestamp DESC LIMIT 50")?;
    
    let history_iter = stmt.query_map([], |row| {
        Ok(ScanHistoryItem {
            scan_id: row.get(0)?,
            filename: row.get(1)?,
            risk_score: row.get(2).unwrap_or(0),
            threat_categories: row.get(3)?,
            timestamp: row.get(4)?,
        })
    })?;

    let mut results = Vec::new();
    for item in history_iter {
        if let Ok(i) = item {
            results.push(i);
        }
    }
    Ok(results)
}
