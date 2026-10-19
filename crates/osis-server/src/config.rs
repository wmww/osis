//! The binary's config file: `key = value` lines; `#` at a line start or after whitespace starts
//! a comment (an address's `url#key` has none before it); blank lines ignored.
//!
//! ```text
//! listen = quic://0.0.0.0:7400        # transport URL to listen on
//! key = /var/lib/osis/server.key      # 32-byte static secret (created if missing)
//! data = /var/lib/osis                # data directory (server.redb inside)
//! peer = quic://b.example:7400#<key>  # replication peer, repeatable (address text form)
//! cap_entries = 1048576               # policy knobs, all optional (`Policy` field names)
//! ```

use crate::store::Policy;
use osis_label::{Address, address_from_text};
use std::path::PathBuf;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    pub listen: String,
    pub key: PathBuf,
    pub data: PathBuf,
    pub peers: Vec<Address>,
    pub policy: Policy,
}

pub fn parse(text: &str) -> Result<Config, String> {
    let (mut listen, mut key, mut data, mut peers, mut p) = (None, None, None, Vec::new(), Policy::default());
    for (i, line) in text.lines().enumerate() {
        let line = strip_comment(line).trim();
        if line.is_empty() {
            continue;
        }
        let bad = |what: &str| format!("line {}: {what}", i + 1);
        let (k, v) = line.split_once('=').ok_or_else(|| bad("expected key = value"))?;
        let (k, v) = (k.trim(), v.trim());
        let n = || v.parse::<u64>().map_err(|_| bad("expected a number"));
        let n32 = || v.parse::<u32>().map_err(|_| bad("expected a number"));
        match k {
            "listen" => listen = Some(v.to_string()),
            "key" => key = Some(PathBuf::from(v)),
            "data" => data = Some(PathBuf::from(v)),
            "peer" => peers.push(address_from_text(v).map_err(|e| bad(&format!("peer address: {e}")))?),
            "cap_entries" => p.cap_entries = n()?,
            "cap_bytes" => p.cap_bytes = n()?,
            "deposit_factor" => p.deposit_factor = n()?,
            "claim_keep_ms" => p.claim_keep_ms = n()?,
            "tombstone_ms" => p.tombstone_ms = n()?,
            "log_keep" => p.log_keep = n()?,
            "window_ms" => p.window_ms = n()?,
            "deletes" => p.deletes = n32()?,
            "replacements" => p.replacements = n32()?,
            "deposits" => p.deposits = n32()?,
            "signals" => p.signals = n32()?,
            "entry_replacements" => p.entry_replacements = n32()?,
            _ => return Err(bad(&format!("unknown key {k}"))),
        }
    }
    Ok(Config { listen: listen.ok_or("missing listen")?, key: key.ok_or("missing key")?, data: data.ok_or("missing data")?, peers, policy: p })
}

fn strip_comment(line: &str) -> &str {
    let mut prev_space = true;
    for (i, c) in line.char_indices() {
        if c == '#' && prev_space {
            return line.get(..i).unwrap_or("");
        }
        prev_space = c.is_whitespace();
    }
    line
}

#[cfg(test)]
mod tests {
    use super::*;

    // spec: none (server config file)
    #[test]
    fn parses_keys_peers_and_knobs() {
        let peer = osis_label::address_to_text(&Address { url: "quic://b:7400".into(), key: [7; 32] });
        let text = format!("# server\nlisten = quic://0.0.0.0:7400\nkey = /k\ndata = /d  # dir\npeer = {peer}\n\nsignals = 5\ncap_bytes = 1000\n");
        let c = parse(&text).unwrap();
        assert_eq!(c.listen, "quic://0.0.0.0:7400");
        assert_eq!(c.data, PathBuf::from("/d"));
        assert_eq!(c.peers, vec![Address { url: "quic://b:7400".into(), key: [7; 32] }]);
        assert_eq!((c.policy.signals, c.policy.cap_bytes, c.policy.deposits), (5, 1000, Policy::default().deposits));
        assert!(parse("listen = x\nkey = k\n").is_err());
        assert!(parse("listen = x\nkey = k\ndata = d\nbogus = 1\n").is_err());
        assert!(parse("listen = x\nkey = k\ndata = d\nsignals = many\n").is_err());
    }
}
