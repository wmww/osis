//! The binary's config file: `key = value` lines; `#` at a line start or after whitespace starts
//! a comment (an address's `url#key` has none before it); blank lines ignored.
//!
//! ```text
//! listen = quic://0.0.0.0:7400        # required: transport URL to listen on
//! key = /var/lib/osis/server.key      # required: 32-byte static secret (created if missing)
//! data = /var/lib/osis                # data directory, server.redb inside (default: osis-server-data)
//! peer = quic://b.example:7400#<key>  # replication peer, repeatable (address text form)
//! cap_entries = 1048576               # policy knobs, all optional (`Policy` field names)
//! ```

use crate::store::Policy;
use osis_label::{Address, address_from_text};
use osis_proto::client::WINDOW_QUEUE as MIN_QUEUED;
use std::path::PathBuf;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    pub listen: String,
    pub key: PathBuf,
    pub data: PathBuf,
    pub peers: Vec<Address>,
    pub policy: Policy,
}

/// The data directory when the config names none (relative to the working directory).
pub const DEFAULT_DATA: &str = "osis-server-data";

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
            "ephemeral_bytes" => p.ephemeral_bytes = n()?,
            "ephemeral_total" => p.ephemeral_total = n()?,
            "presence_bytes" => p.presence_bytes = n()?,
            "relays" => p.relays = n32()?,
            "relay_bytes" => p.relay_bytes = n()?,
            "entry_replacements" => p.entry_replacements = n32()?,
            "max_labels" => p.max_labels = n()?,
            "max_entries" => p.max_entries = n()?,
            "max_bytes" => p.max_bytes = n()?,
            "max_connections" => p.max_connections = usize::try_from(n()?).map_err(|_| bad("too large"))?,
            "hello_ms" => p.hello_ms = n()?,
            "max_queued_bytes" => {
                p.max_queued_bytes = usize::try_from(n()?).map_err(|_| bad("too large"))?;
                if p.max_queued_bytes < MIN_QUEUED {
                    return Err(bad(&format!("below {MIN_QUEUED} (a client's window plus a message, spec/sync.md §6)")));
                }
            }
            "max_buffered_bytes" => p.max_buffered_bytes = usize::try_from(n()?).map_err(|_| bad("too large"))?,
            _ => return Err(bad(&format!("unknown key {k}"))),
        }
    }
    Ok(Config { listen: listen.ok_or("missing listen")?, key: key.ok_or("missing key")?, data: data.unwrap_or_else(|| PathBuf::from(DEFAULT_DATA)), peers, policy: p })
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
        let text = format!("# server\nlisten = quic://0.0.0.0:7400\nkey = /k\ndata = /d  # dir\npeer = {peer}\n\nephemeral_bytes = 5\ncap_bytes = 1000\n");
        let c = parse(&text).unwrap();
        assert_eq!(c.listen, "quic://0.0.0.0:7400");
        assert_eq!(c.data, PathBuf::from("/d"));
        assert_eq!(c.peers, vec![Address { url: "quic://b:7400".into(), key: [7; 32] }]);
        assert_eq!((c.policy.ephemeral_bytes, c.policy.cap_bytes, c.policy.deposits), (5, 1000, Policy::default().deposits));
        assert_eq!(parse("listen = x\nkey = k\nmax_connections = 3\n").unwrap().data, PathBuf::from(DEFAULT_DATA));
        assert!(parse("listen = x\n").is_err());
        assert!(parse("listen = x\nkey = k\ndata = d\nbogus = 1\n").is_err());
        assert!(parse("listen = x\nkey = k\ndata = d\nephemeral_bytes = many\n").is_err());
        assert!(parse(&format!("listen = x\nkey = k\nmax_queued_bytes = {}\n", MIN_QUEUED - 1)).is_err());
        assert!(parse(&format!("listen = x\nkey = k\nmax_queued_bytes = {MIN_QUEUED}\n")).is_ok());
        assert!(Policy::default().max_queued_bytes >= MIN_QUEUED);
    }
}
