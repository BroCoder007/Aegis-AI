use serde::{Deserialize, Serialize};

#[derive(Debug, Default, Clone)]
pub struct VTReport {
    pub malicious: u32,
    pub harmless: u32,
    pub undetected: u32,
    pub suspicious: u32,
    pub total: u32,
    pub permalink: String,
}

pub async fn check_hash(hash: &str) -> Option<VTReport> {
    // We hardcode the provided API key here. In production, consider loading this from .env or Tauri state config.
    let api_key = "725a15cb5a2269acaa934544e532d6b0417ad9a6a5484c6b49877f01c1d5b8f9";
    let url = format!("https://www.virustotal.com/api/v3/files/{}", hash);

    let client = reqwest::Client::new();
    let res = client.get(&url).header("x-apikey", api_key).send().await.ok()?;

    if res.status().is_success() {
        let json: serde_json::Value = res.json().await.ok()?;
        
        let stats = &json["data"]["attributes"]["last_analysis_stats"];
        let malicious = stats["malicious"].as_u64().unwrap_or(0) as u32;
        let harmless = stats["harmless"].as_u64().unwrap_or(0) as u32;
        let undetected = stats["undetected"].as_u64().unwrap_or(0) as u32;
        let suspicious = stats["suspicious"].as_u64().unwrap_or(0) as u32;
        let total = malicious + harmless + undetected + suspicious;

        Some(VTReport {
            malicious,
            harmless,
            undetected,
            suspicious,
            total,
            permalink: format!("https://www.virustotal.com/gui/file/{}", hash),
        })
    } else {
        None // Usually a 404 if the hash has never been seen by VT
    }
}
