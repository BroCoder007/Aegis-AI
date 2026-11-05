use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    path::Path,
    time::Duration,
};
#[derive(Clone, Serialize, Deserialize)]
pub struct EngineConfig {
    pub address: String,
}
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Verdict {
    pub status: String,
    pub detail: String,
    pub sha256: Option<String>,
}
fn connect(config: &EngineConfig) -> Result<TcpStream, String> {
    let address: SocketAddr = config
        .address
        .parse()
        .map_err(|_| "Use a loopback IP:port, for example 127.0.0.1:3310")?;
    if !address.ip().is_loopback() {
        return Err("Only a loopback ClamAV daemon is allowed".into());
    }
    let stream =
        TcpStream::connect_timeout(&address, Duration::from_secs(3)).map_err(|e| e.to_string())?;
    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .map_err(|e| e.to_string())?;
    stream
        .set_write_timeout(Some(Duration::from_secs(30)))
        .map_err(|e| e.to_string())?;
    Ok(stream)
}
fn response(stream: &mut TcpStream) -> Result<String, String> {
    let mut bytes = Vec::new();
    let mut b = [0u8; 1];
    while stream.read(&mut b).map_err(|e| e.to_string())? > 0 {
        if b[0] == 0 || b[0] == b'\n' {
            break;
        }
        bytes.push(b[0]);
        if bytes.len() > 65536 {
            return Err("Daemon response exceeds limit".into());
        }
    }
    String::from_utf8(bytes).map_err(|e| e.to_string())
}
pub fn version(config: &EngineConfig) -> Result<String, String> {
    let mut s = connect(config)?;
    s.write_all(b"zVERSION\0").map_err(|e| e.to_string())?;
    response(&mut s)
}
pub fn scan(config: &EngineConfig, path: &Path, limit: u64) -> Verdict {
    let result = (|| -> Result<Verdict, String> {
        let mut file = std::fs::File::open(path).map_err(|e| e.to_string())?;
        let before = file.metadata().map_err(|e| e.to_string())?;
        if !before.is_file() || before.len() > limit {
            return Err("File is not regular or exceeds cap".into());
        }
        let mut stream = connect(config)?;
        stream
            .write_all(b"zINSTREAM\0")
            .map_err(|e| e.to_string())?;
        let mut digest = sha2::Sha256::new();
        let mut bytes = 0u64;
        let mut buf = [0u8; 65536];
        loop {
            let n = file.read(&mut buf).map_err(|e| e.to_string())?;
            if n == 0 {
                break;
            }
            bytes += n as u64;
            digest.update(&buf[..n]);
            if bytes > limit {
                return Err("File grew beyond cap".into());
            }
            stream
                .write_all(&(n as u32).to_be_bytes())
                .and_then(|_| stream.write_all(&buf[..n]))
                .map_err(|e| e.to_string())?;
        }
        stream
            .write_all(&0u32.to_be_bytes())
            .map_err(|e| e.to_string())?;
        let detail = response(&mut stream)?;
        let after = file.metadata().map_err(|e| e.to_string())?;
        if before.len() != after.len() || before.modified().ok() != after.modified().ok() {
            return Err("File changed during signature scan".into());
        }
        let status = if detail.ends_with(" FOUND") {
            "detected"
        } else if detail.ends_with(" OK") {
            "no_known_match"
        } else {
            "error"
        };
        Ok(Verdict {
            status: status.into(),
            detail,
            sha256: Some(hex::encode(digest.finalize())),
        })
    })();
    result.unwrap_or_else(|e| Verdict {
        status: "error".into(),
        detail: e,
        sha256: None,
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn remote_is_rejected() {
        assert!(version(&EngineConfig {
            address: "1.1.1.1:3310".into()
        })
        .is_err());
    }
    #[test]
    fn mock_daemon_detects() {
        use std::net::TcpListener;
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap().to_string();
        let thread = std::thread::spawn(move || {
            let (mut s, _) = l.accept().unwrap();
            let mut command = [0u8; 10];
            s.read_exact(&mut command).unwrap();
            assert_eq!(&command, b"zINSTREAM\0");
            loop {
                let mut size = [0; 4];
                s.read_exact(&mut size).unwrap();
                let n = u32::from_be_bytes(size) as usize;
                if n == 0 {
                    break;
                }
                let mut payload = vec![0; n];
                s.read_exact(&mut payload).unwrap();
            }
            s.write_all(b"stream: Test.Signature FOUND\0").unwrap();
        });
        let file = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
        std::fs::write(&file, b"synthetic fixture").unwrap();
        assert_eq!(
            scan(&EngineConfig { address: addr }, &file, 100).status,
            "detected"
        );
        thread.join().unwrap();
        std::fs::remove_file(file).unwrap();
    }
}
