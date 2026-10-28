//! The binary's main as a call (feature `bin`): the `osis-server` binary and the CLI's `osis
//! serve` run a blind node on the redb file backend over QUIC until Ctrl-C (SIGINT).

use crate::{BackendStore, Config, Control, Endpoint, Hub, Log, driver};
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
    let store = BackendStore::open(backend, clock.clone(), cfg.policy.clone(), &mut OsRng).map_err(|e| e.to_string())?;
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
