use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::{Read, BufReader};
use uuid::Uuid;
use sha2::{Sha256, Digest};

#[derive(Debug, Serialize, Deserialize)]
pub struct TelemetryData {
    pub scan_id: String,
    pub target_file: String,
    pub sha256_hash: String,
    pub syscalls: Vec<String>,
    pub dns_requests: Vec<String>,
    pub dropped_files: Vec<String>,
    pub triggered_yara_rules: Vec<String>,
    pub triggered_behavioral_flags: Vec<String>,
}

pub async fn simulate_sandbox_execution(file_path: &str) -> TelemetryData {
    let scan_id = Uuid::new_v4().to_string();
    
    // 1. Safety Check: Enforce 50MB File Limit
    let meta = match fs::metadata(file_path) {
        Ok(m) => m,
        Err(_) => return build_error_telemetry(scan_id, file_path, "ERROR_READING_METADATA"),
    };

    if meta.len() > 50 * 1024 * 1024 {
        return build_error_telemetry(scan_id, file_path, "FILE_TOO_LARGE_50MB_LIMIT");
    }

    let file = match File::open(file_path) {
        Ok(f) => f,
        Err(_) => return build_error_telemetry(scan_id, file_path, "ERROR_OPENING_FILE"),
    };

    // 2. Cryptographic Sha256 Fingerprint (Chunked Streaming)
    let mut reader = BufReader::new(file);
    let mut hasher = Sha256::new();
    let mut buffer = [0; 8192]; // 8KB chunks
    
    // We also need the full bytes for Goblin and String scraping, so we capture them while hashing
    let mut bytes = Vec::with_capacity(meta.len() as usize);

    loop {
        let count = match reader.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => n,
            Err(_) => return build_error_telemetry(scan_id, file_path, "ERROR_STREAMING_FILE"),
        };
        hasher.update(&buffer[..count]);
        bytes.extend_from_slice(&buffer[..count]);
    }
    
    let sha256_hash = hex::encode(hasher.finalize());

    // 3. Heuristic String Scraper for Network / Filesystem hooks hidden in code
    let mut dns_requests = Vec::new();
    let mut dropped_files = Vec::new();
    
    let mut current_string = String::new();
    for &b in &bytes {
        if b.is_ascii_graphic() || b == b' ' || b == b'.' || b == b'/' || b == b'\\' {
            current_string.push(b as char);
        } else {
            if current_string.len() > 5 {
                let s = current_string.to_lowercase();
                if s.contains("http://") || s.contains("https://") || s.contains(".com") || s.contains(".xyz") || s.contains(".org") || s.contains(".net") {
                    dns_requests.push(current_string.clone());
                } else if s.contains("c:\\") || s.contains(".exe") || s.contains(".dll") || s.contains(".sys") {
                    dropped_files.push(current_string.clone());
                }
            }
            current_string.clear();
        }
    }

    dns_requests.sort();
    dns_requests.dedup();
    dropped_files.sort();
    dropped_files.dedup();

    let dns_requests: Vec<String> = dns_requests.into_iter().take(20).collect();
    let dropped_files: Vec<String> = dropped_files.into_iter().take(20).collect();

    // 4. Goblin PE Header Parsing for Imported Syscalls Functions
    let mut syscalls = Vec::new();
    if let Ok(obj) = goblin::Object::parse(&bytes) {
        match obj {
            goblin::Object::PE(pe) => {
                for import in pe.imports {
                    syscalls.push(import.name.to_string());
                }
            },
            _ => {}
        }
    }
    
    syscalls.sort();
    syscalls.dedup();
    let syscalls: Vec<String> = syscalls.into_iter().take(50).collect();

    // 5. DETERMISTIC BOUNCER ENGINE
    // We implement the deterministic logic directly to execute thousands of conditional parameters instantly natively in Rust

    let mut triggered_yara_rules = Vec::new();
    let mut triggered_behavioral_flags = Vec::new();

    // Bouncer Rule A: Remote Thread Injection Payload
    let has_injection_api = syscalls.iter().any(|s| s.contains("CreateRemoteThread") || s.contains("VirtualAllocEx") || s.contains("WriteProcessMemory"));
    if has_injection_api {
        triggered_behavioral_flags.push("Suspicious Memory Injection APIs Detected".to_string());
        triggered_yara_rules.push("YARA_RULE: ProcessHollowing_Win32".to_string());
    }

    // Bouncer Rule B: Keylogging / Screen Scraping
    let has_keylogger_api = syscalls.iter().any(|s| s.contains("SetWindowsHookEx") || s.contains("GetAsyncKeyState"));
    if has_keylogger_api {
        triggered_behavioral_flags.push("Potential User Input Interception (Keylogger)".to_string());
        triggered_yara_rules.push("YARA_RULE: Keylogger_API_Sequence".to_string());
    }

    // Bouncer Rule C: Ransomware Cryptography
    let has_crypto_api = syscalls.iter().any(|s| s.contains("CryptEncrypt") || s.contains("CryptGenKey"));
    if has_crypto_api {
        triggered_behavioral_flags.push("Encryption APIs Loaded (Ransomware Warning)".to_string());
    }

    // Bouncer Rule D: Network Exfiltration + Dropper
    let has_network = !dns_requests.is_empty();
    let has_dropper = dropped_files.iter().any(|s| s.contains(".exe") || s.contains(".sys"));
    
    if has_network && has_dropper {
        triggered_behavioral_flags.push("Network Comms paired with EXE Dropping (Trojan Indicator)".to_string());
        triggered_yara_rules.push("YARA_RULE: Trojan_Dropper_Generic".to_string());
    }

    // Bouncer Rule E: Anti-Analysis & Timing Attacks (The "Shy" Malware)
    let has_evasion_api = syscalls.iter().any(|s| s.contains("IsDebuggerPresent") || s.contains("Sleep") || s.contains("GetTickCount") || s.contains("QueryPerformanceCounter"));
    if has_evasion_api {
        triggered_behavioral_flags.push("Anti-Analysis Timing or Debugger Evasion Checks".to_string());
        triggered_yara_rules.push("SIGMA_RULE: Suspicious_Evasion_API_Sequence".to_string());
    }

    // Bouncer Rule F: Hardware VM Profiling
    let has_hw_profiling = syscalls.iter().any(|s| s.contains("GlobalMemoryStatusEx") || s.contains("GetSystemInfo"));
    if has_hw_profiling {
        triggered_behavioral_flags.push("Hardware Fingerprinting (Potential VM/Sandbox Detection)".to_string());
    }

    // Bouncer Rule G: The Downloader Chain
    let has_downloader_api = syscalls.iter().any(|s| s.contains("URLDownloadToFile"));
    let has_execution_api = syscalls.iter().any(|s| s.contains("ShellExecute") || s.contains("CreateProcess"));
    if has_downloader_api && has_execution_api {
        triggered_behavioral_flags.push("Multi-Stage Downloader & Execution Chain".to_string());
        triggered_yara_rules.push("YARA_RULE: Downloader_Execution_Chain".to_string());
    }

    // Bouncer Rule H: Ransomware Iteration Chain
    let has_find_files = syscalls.iter().any(|s| s.contains("FindFirstFile") || s.contains("FindNextFile"));
    let has_crypto = syscalls.iter().any(|s| s.contains("CryptAcquireContext") || s.contains("CryptEncrypt"));
    let interacts_vssadmin = bytes.windows(12).any(|w| w.eq_ignore_ascii_case(b"vssadmin.exe"));
    if has_find_files && has_crypto {
        triggered_behavioral_flags.push("File Iteration + Crypto APIs Loaded (Ransomware Signatures)".to_string());
        if interacts_vssadmin {
            triggered_yara_rules.push("YARA_RULE: Ransomware_VSSAdmin_Deletion".to_string());
        }
    }

    // Bouncer Rule I: File System & Registry Persistence
    let writes_to_run_keys = bytes.windows(44).any(|w| w.eq_ignore_ascii_case(b"Software\\Microsoft\\Windows\\CurrentVersion\\Run"));
    let drops_appdata = dropped_files.iter().any(|s| s.contains("appdata\\roaming"));
    if writes_to_run_keys {
        triggered_behavioral_flags.push("Registry Persistence (Run Keys) Modification".to_string());
        triggered_yara_rules.push("MITRE_T1060: Registry_Run_Keys".to_string());
    }
    if drops_appdata && has_dropper {
        triggered_behavioral_flags.push("Suspicious Dropper to AppData\\Roaming".to_string());
    }

    TelemetryData {
        scan_id,
        target_file: file_path.to_string(),
        sha256_hash,
        syscalls,
        dns_requests,
        dropped_files,
        triggered_yara_rules,
        triggered_behavioral_flags,
    }
}

fn build_error_telemetry(scan_id: String, target_file: &str, err_hash: &str) -> TelemetryData {
    TelemetryData {
        scan_id,
        target_file: target_file.to_string(),
        sha256_hash: err_hash.to_string(),
        syscalls: vec![],
        dns_requests: vec![],
        dropped_files: vec![],
        triggered_yara_rules: vec![],
        triggered_behavioral_flags: vec!["FileReadError".to_string()],
    }
}
