//! `lan/`: a LAN announcement datagram (spec/sync.md §10, provisional). Generated. Dialable
//! seed `08`, lan secret `0c`, transport key `0d`, port 47381, unix ms 1_700_000_000_000.

use super::{case, generated_header, s32};
use crate::file::VecFile;
use crate::hex;
use osis_crypto::{SigningSecret, lan_digest, lan_tag, open_lan_sig, seal_lan_sig};

const SPEC: &str = "spec/sync.md §10";

pub fn announce() -> VecFile {
    let dialable = SigningSecret::from_seed(&s32(0x08));
    let lan = s32(0x0c);
    let key = [0x0d; 32];
    let (port, ms) = (47_381u16, 1_700_000_000_000u64);
    let window = ms / 600_000;
    let tag = lan_tag(&lan, ms);
    let digest = lan_digest(&tag, &key, port);
    let sealed = seal_lan_sig(&dialable, &lan, window, &tag, &key, port);
    assert!(open_lan_sig(&dialable.verifying_key(), &lan, window, &tag, &key, port, &sealed));
    let mut datagram = b"osis lan 1".to_vec();
    datagram.extend_from_slice(&tag);
    datagram.extend_from_slice(&key);
    datagram.extend_from_slice(&port.to_be_bytes());
    datagram.extend_from_slice(&sealed);
    let cases = vec![
        case("announce", SPEC)
            .with("dialable-seed", hex(s32(0x08).expose()))
            .with("dialable", hex(&dialable.verifying_key().to_bytes()))
            .with("lan-secret", hex(lan.expose()))
            .with("unix-ms", ms.to_string())
            .with("window", window.to_string())
            .with("key", hex(&key))
            .with("port", port.to_string())
            .with("tag", hex(&tag))
            .with("digest", hex(&digest))
            .with("datagram", hex(&datagram)),
    ];
    VecFile { header: generated_header("lan", SPEC), cases }
}
