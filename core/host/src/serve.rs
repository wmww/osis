//! `osis serve`'s body: hosts on the redb file backend over QUIC until Ctrl-C (SIGINT).

use crate::{HostStore, Config, Control, Endpoint, Hub, Log, driver};
use osis_base::SystemClock;
use osis_crypto::{OsRng, RngCore};
use osis_store::RedbBackend;
use osis_transport::{ListenConfig, Listener, Quic, StaticSecret, Transport};
use std::path::Path;
use std::sync::Arc;

/// The 32-byte static secret at `path`, created (owner-only) if missing.
pub fn static_secret(path: &Path, log: &Log) -> Result<[u8; 32], String> {
    match std::fs::read(path) {
        Ok(b) => {
            #[cfg(unix)]
            if let Ok(m) = std::fs::metadata(path)
                && std::os::unix::fs::PermissionsExt::mode(&m.permissions()) & 0o077 != 0
            {
                log(&format!("warning: {} is readable by others (want mode 0600)", path.display()));
            }
            b.try_into().map_err(|_| format!("{}: not a 32-byte key", path.display()))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let mut k = [0u8; 32];
            OsRng.fill_bytes(&mut k);
            let mut o = std::fs::OpenOptions::new();
            o.write(true).create_new(true);
            #[cfg(unix)]
            std::os::unix::fs::OpenOptionsExt::mode(&mut o, 0o600);
            let mut f = o.open(path).map_err(|e| format!("{}: {e}", path.display()))?;
            std::io::Write::write_all(&mut f, &k).map_err(|e| format!("{}: {e}", path.display()))?;
            f.sync_all().map_err(|e| format!("{}: {e}", path.display()))?;
            log(&format!("created static key {}", path.display()));
            Ok(k)
        }
        Err(e) => Err(format!("{}: {e}", path.display())),
    }
}

/// Serves until Ctrl-C. `address` gets the bound address text (`<url>#<key>`) once listening.
pub fn run(cfg: Config, log: Log, address: impl FnOnce(&str)) -> Result<(), String> {
    let secret = static_secret(&cfg.key, &log)?;
    std::fs::create_dir_all(&cfg.data).map_err(|e| format!("{}: {e}", cfg.data.display()))?;
    let backend = RedbBackend::open(&cfg.data.join("server.redb")).map_err(|e| e.to_string())?;
    let clock = Arc::new(SystemClock);
    let store = HostStore::open(backend, clock.clone(), cfg.policy.clone(), &mut OsRng).map_err(|e| e.to_string())?;
    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build().map_err(|e| e.to_string())?;
    rt.block_on(async move {
        let secret = StaticSecret::from_bytes(secret);
        let transport = Quic::new();
        let listener = transport.listen(ListenConfig { url: cfg.listen.clone(), secret: secret.clone() }).await.map_err(|e| format!("listen {}: {e}", cfg.listen))?;
        let a = listener.address();
        address(&osis_label::address_to_text(&osis_label::Address { url: a.url, key: a.key }));
        let ep = Endpoint { transport, listener, secret };
        let hub = Hub::new(store, ep.key(), Box::new(OsRng));
        let (control, rx) = tokio::sync::mpsc::channel(4);
        let l = log.clone();
        tokio::spawn(async move {
            match tokio::signal::ctrl_c().await {
                Ok(()) => {
                    l("shutting down");
                    let _ = control.send(Control::Shutdown).await;
                }
                Err(e) => {
                    // No signal handling: keep running (and keep the control channel open).
                    l(&format!("cannot watch for Ctrl-C: {e}"));
                    std::future::pending::<()>().await;
                    drop(control);
                }
            }
        });
        driver::run(hub, ep, cfg.peers, clock, rx, log).await;
        Ok::<(), String>(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // spec/sync.md §10: the static key file `osis serve` uses is created owner-only (0600) and read
    // back unchanged; a file of another length is refused (`osis serve` itself: osis-cli
    // tests/it/localhost.rs)
    #[test]
    fn static_key_file_created_owner_only() {
        let dir = std::env::temp_dir().join(format!("osis-host-key-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("key");
        let log: Log = Arc::new(|m: &str| eprintln!("{m}"));
        let k = static_secret(&path, &log).unwrap();
        #[cfg(unix)]
        assert_eq!(std::os::unix::fs::PermissionsExt::mode(&std::fs::metadata(&path).unwrap().permissions()) & 0o777, 0o600);
        assert_eq!(static_secret(&path, &log).unwrap(), k);
        std::fs::write(&path, [1u8; 31]).unwrap();
        assert!(static_secret(&path, &log).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
