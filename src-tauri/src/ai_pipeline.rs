use crate::orchestrator::TelemetryData;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct ThreatAnalysisReport {
    pub risk_score: u8, // 1-100
    pub threat_categories: Vec<String>,
    pub plain_english_explanation: String,
    #[serde(default)]
    pub bouncer_yara: Vec<String>,
    #[serde(default)]
    pub bouncer_behavioral: Vec<String>,
}

/// Evaluates raw telemetry using an LLM.
pub async fn evaluate_telemetry(telemetry: &TelemetryData, vt_report: Option<crate::threat_intel::VTReport>) -> Result<ThreatAnalysisReport, String> {
    
    let mut vt_string = String::new();
    if let Some(vt) = vt_report {
        vt_string = format!(
            "VIRUSTOTAL THREAT INTEL: {}/{} Security Vendors flagged this file as malicious.\n",
            vt.malicious, vt.total
        );
    }

    let prompt = format!(
        "You are an Expert Cybersecurity Malware Analyst. Perform a final risk synthesis for the file '{}'.\n\n\
        STATIC ARTIFACTS:\n\
        Syscalls: {:?}\n\
        Domains: {:?}\n\n\
        DETERMINISTIC ENGINE ALERTS:\n\
        The following highly specific behavioral and signature rules were triggered by our internal engines:\n\
        YARA Matches: {:?}\n\
        Behavioral Flags: {:?}\n\n\
        {}\
        INSTRUCTIONS:\n\
        Your job is not to find the anomalies, but to synthesize them. Look at the specific YARA matches, Behavioral flags, and VT Intel triggered above. Correlate them with the raw syscalls and domains.\n\
        Output your analysis strictly as a JSON object with no markdown formatting. The JSON must match this exact schema:\n\
        {{\n\
            \"risk_score\": <integer between 1 and 100>,\n\
            \"threat_categories\": [\"<category1>\", \"<category2>\"],\n\
            \"plain_english_explanation\": \"<short explanation detailing how these triggered determinist alerts work together to form an attack chain>\"\n\
        }}",
        telemetry.target_file, telemetry.syscalls, telemetry.dns_requests, telemetry.triggered_yara_rules, telemetry.triggered_behavioral_flags, vt_string
    );

    let client = reqwest::Client::new();

    let payload = serde_json::json!({
        "model": "deepseek-r1:32b",
        "prompt": prompt,
        "stream": false
        // Removed "format": "json" because it destroys DeepSeek R1's ability to output <think> tokens, ruining its intelligence.
    });

    let res = client
        .post("http://localhost:11434/api/generate")
        .json(&payload)
        .send()
        .await
        .map_err(|e| format!("Failed to reach Ollama HTTP Daemon. Is it running? Error: {}", e))?;

    if !res.status().is_success() {
        let err_text = res.text().await.unwrap_or_else(|_| "Unknown Error".to_string());
        return Err(format!("Ollama HTTP API failed with status: {}. Details: {}", err_text, err_text));
    }

    let json_res: serde_json::Value = res.json().await.map_err(|e| format!("Failed to parse HTTP JSON: {}", e))?;
    
    let generated_text = json_res["response"]
        .as_str()
        .ok_or_else(|| "Ollama API response did not contain a 'response' string field.".to_string())?;

    // DeepSeek R1 outputs <think>...</think> reasoning blocks before its JSON. We extract only the JSON.
    let json_start = generated_text.find('{').unwrap_or(0);
    let json_end = generated_text.rfind('}').unwrap_or(generated_text.len().saturating_sub(1));
    
    let cleaned_json = if json_start <= json_end && json_end < generated_text.len() {
        &generated_text[json_start..=json_end]
    } else {
        generated_text
    };

    // Parse the JSON representation into our Rust struct
    let mut report: ThreatAnalysisReport = serde_json::from_str(cleaned_json)
        .map_err(|e| format!("Ollama returned poorly formatted JSON: {} \n\nRaw Text: {}", e, generated_text))?;

    report.bouncer_yara = telemetry.triggered_yara_rules.clone();
    report.bouncer_behavioral = telemetry.triggered_behavioral_flags.clone();

    Ok(report)
}
