use aes_gcm::{
    aead::{rand_core::RngCore, Aead, OsRng},
    Aes256Gcm, KeyInit, Nonce,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::Mutex,
};
static LOCK: Mutex<()> = Mutex::new(());
const CAP: u64 = 32 * 1024 * 1024;
#[derive(Clone, Serialize, Deserialize)]
pub struct Entry {
    pub id: String,
    pub original: String,
    pub sha256: String,
    pub state: String,
    pub note: String,
}
fn paths(dir: &Path, id: &str) -> Result<(PathBuf, PathBuf, PathBuf), String> {
    uuid::Uuid::parse_str(id).map_err(|_| "Invalid quarantine ID")?;
    Ok((
        dir.join(format!("{id}.json")),
        dir.join(format!("{id}.pending")),
        dir.join(format!("{id}.data")),
    ))
}
fn prepare(dir: &Path) -> Result<(), String> {
    fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700)).map_err(|e| e.to_string())?;
    }
    Ok(())
}
fn key(dir: &Path) -> Result<Vec<u8>, String> {
    let path = dir.join("key.bin");
    if path.exists() {
        let b = fs::read(path).map_err(|e| e.to_string())?;
        if b.len() != 32 {
            return Err("Invalid quarantine key".into());
        }
        return Ok(b);
    }
    let mut bytes = vec![0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut f = options.open(path).map_err(|e| e.to_string())?;
    f.write_all(&bytes)
        .and_then(|_| f.sync_all())
        .map_err(|e| e.to_string())?;
    Ok(bytes)
}
fn read_capped(path: &Path) -> Result<Vec<u8>, String> {
    let meta = fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    if meta.file_type().is_symlink() {
        return Err("Staged links cannot be read".into());
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if meta.file_attributes() & 0x400 != 0 {
            return Err("Staged reparse points cannot be read".into());
        }
    }
    let f = fs::File::open(path).map_err(|e| e.to_string())?;
    if !f.metadata().map_err(|e| e.to_string())?.is_file() {
        return Err("Not a regular file".into());
    }
    let mut b = Vec::new();
    f.take(CAP + 1)
        .read_to_end(&mut b)
        .map_err(|e| e.to_string())?;
    if b.len() as u64 > CAP {
        return Err("Quarantine supports files up to 32 MiB".into());
    }
    Ok(b)
}
fn save(path: &Path, e: &Entry) -> Result<(), String> {
    let bytes = serde_json::to_vec_pretty(e).map_err(|e| e.to_string())?;
    let temporary = path.with_extension(format!("{}.tmp", uuid::Uuid::new_v4()));
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .map_err(|e| e.to_string())?;
    f.write_all(&bytes)
        .and_then(|_| f.sync_all())
        .map_err(|e| e.to_string())?;
    drop(f);
    fs::rename(temporary, path).map_err(|e| e.to_string())
}
pub fn list(dir: &Path) -> Result<Vec<Entry>, String> {
    prepare(dir)?;
    let mut entries = Vec::new();
    for file in fs::read_dir(dir).map_err(|e| e.to_string())?.take(2000) {
        let path = file.map_err(|e| e.to_string())?.path();
        if path.extension().and_then(|x| x.to_str()) == Some("json") {
            if let Ok(bytes) = fs::read(&path) {
                if let Ok(e) = serde_json::from_slice::<Entry>(&bytes) {
                    entries.push(e);
                }
            }
        }
    }
    Ok(entries)
}
pub fn put(dir: &Path, source: &Path, expected: &str) -> Result<Entry, String> {
    let _guard = LOCK.lock().map_err(|e| e.to_string())?;
    prepare(dir)?;
    let meta = fs::symlink_metadata(source).map_err(|e| e.to_string())?;
    if !meta.is_file() || meta.file_type().is_symlink() || meta.len() > CAP {
        return Err("Select a regular non-link file up to 32 MiB".into());
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if meta.file_attributes() & 0x400 != 0 {
            return Err("Reparse points cannot be quarantined".into());
        }
    }
    let cipher = Aes256Gcm::new_from_slice(&key(dir)?).map_err(|e| e.to_string())?;
    let id = uuid::Uuid::new_v4().to_string();
    let (manifest, stage, blob) = paths(dir, &id)?;
    let mut entry = Entry {
        id,
        original: source.to_string_lossy().to_string(),
        sha256: expected.into(),
        state: "pending".into(),
        note: "Manual quarantine; not proof of malware".into(),
    };
    save(&manifest, &entry)?;
    if let Err(e) = fs::rename(source, &stage) {
        let _ = fs::remove_file(&manifest);
        return Err(format!(
            "Cannot move into quarantine (same volume required): {e}"
        ));
    }
    let bytes = read_capped(&stage)?;
    let actual = hex::encode(Sha256::digest(&bytes));
    entry.sha256 = actual.clone();
    save(&manifest, &entry)?;
    if actual != expected {
        if fs::hard_link(&stage, source).is_ok() {
            let _ = fs::remove_file(&stage);
            let _ = fs::remove_file(&manifest);
        }
        return Err("File changed since scan; quarantine cancelled. If rollback was blocked, recover the pending entry from the vault.".into());
    }
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let encrypted = cipher
        .encrypt(Nonce::from_slice(&nonce), bytes.as_slice())
        .map_err(|_| "Encryption failed; pending file retained for recovery")?;
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&blob)
        .map_err(|e| e.to_string())?;
    f.write_all(&nonce)
        .and_then(|_| f.write_all(&encrypted))
        .and_then(|_| f.sync_all())
        .map_err(|e| e.to_string())?;
    entry.state = "encrypted".into();
    save(&manifest, &entry)?;
    fs::remove_file(stage)
        .map_err(|e| format!("Encrypted copy saved, but plaintext staging cleanup failed: {e}"))?;
    Ok(entry)
}
pub fn restore(dir: &Path, id: &str) -> Result<String, String> {
    let _guard = LOCK.lock().map_err(|e| e.to_string())?;
    let (manifest, stage, blob) = paths(dir, id)?;
    let e: Entry = serde_json::from_slice(&fs::read(&manifest).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    let bytes = if e.state == "encrypted" {
        if fs::metadata(&blob).map_err(|e| e.to_string())?.len() > CAP + 28 {
            return Err("Encrypted payload exceeds cap".into());
        }
        let bytes = fs::read(&blob).map_err(|e| e.to_string())?;
        if bytes.len() < 28 || bytes.len() as u64 > CAP + 28 {
            return Err("Invalid encrypted payload size".into());
        }
        let key_path = dir.join("key.bin");
        let cipher = Aes256Gcm::new_from_slice(&fs::read(key_path).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
        cipher
            .decrypt(Nonce::from_slice(&bytes[..12]), &bytes[12..])
            .map_err(|_| "Quarantine authentication failed")?
    } else {
        read_capped(&stage)?
    };
    if hex::encode(Sha256::digest(&bytes)) != e.sha256 {
        return Err("Quarantine checksum mismatch".into());
    }
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&e.original)
        .map_err(|e| {
            format!("Restore will not overwrite files; original directory must exist: {e}")
        })?;
    f.write_all(&bytes)
        .and_then(|_| f.sync_all())
        .map_err(|e| e.to_string())?;
    if stage.exists() {
        fs::remove_file(stage).map_err(|e| e.to_string())?;
    }
    if blob.exists() {
        fs::remove_file(blob).map_err(|e| e.to_string())?;
    }
    fs::remove_file(manifest).map_err(|e| e.to_string())?;
    Ok(e.original)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn encrypted_roundtrip_refuses_overwrite() {
        let dir = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
        fs::create_dir_all(&dir).unwrap();
        let file = dir.join("test.txt");
        fs::write(&file, b"benign fixture").unwrap();
        let hash = hex::encode(Sha256::digest(b"benign fixture"));
        let e = put(&dir.join("vault"), &file, &hash).unwrap();
        assert!(!file.exists());
        fs::write(&file, b"occupied").unwrap();
        assert!(restore(&dir.join("vault"), &e.id).is_err());
        fs::remove_file(&file).unwrap();
        restore(&dir.join("vault"), &e.id).unwrap();
        assert_eq!(fs::read(file).unwrap(), b"benign fixture");
        fs::remove_dir_all(dir).unwrap();
    }
}

#[cfg(test)]
mod recovery_tests {
    use super::*;
    #[test]
    fn wrong_hash_rolls_back() {
        let dir = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
        fs::create_dir(&dir).unwrap();
        let source = dir.join("source");
        fs::write(&source, b"preserve me").unwrap();
        assert!(put(&dir.join("vault"), &source, "incorrect").is_err());
        assert_eq!(fs::read(source).unwrap(), b"preserve me");
        fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn corruption_is_not_restored() {
        let dir = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
        fs::create_dir(&dir).unwrap();
        let source = dir.join("source");
        fs::write(&source, b"fixture").unwrap();
        let hash = hex::encode(Sha256::digest(b"fixture"));
        let vault = dir.join("vault");
        let e = put(&vault, &source, &hash).unwrap();
        let (_, _, blob) = paths(&vault, &e.id).unwrap();
        let mut bytes = fs::read(&blob).unwrap();
        bytes[15] ^= 1;
        fs::write(blob, bytes).unwrap();
        assert!(restore(&vault, &e.id).is_err());
        assert!(!source.exists());
        fs::remove_dir_all(dir).unwrap();
    }
}
