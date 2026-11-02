//! `judgment/` (spec/permissions.md §5-§6, spec/commits.md §5): generated and replayed by
//! osis-node (`tests/it/judgment.rs`, through the engine); here only the shape is checked: every
//! case has its inputs, its bundle imports (paths and stamps verify) and its order names entries.

use crate::file::VecFile;
use crate::unhex;
use osis_label::{BundleReader, Importer, Record};

pub fn check(f: &VecFile) -> Result<(), String> {
    let mut entries: Vec<(String, usize)> = Vec::new();
    for c in f.live() {
        let name = c.req("case")?;
        for k in ["read-secret", "now", "order"] {
            c.req(k)?;
        }
        let b = c.req("bundle")?;
        let n = match b.strip_prefix("as in ") {
            Some(other) => entries.iter().find(|(x, _)| x == other).map(|x| x.1).ok_or_else(|| format!("{name}: no earlier case {other}"))?,
            None => {
                let bytes = unhex(b)?;
                let mut rd = BundleReader::new(&bytes[..]).map_err(|e| format!("{name}: {e:?}"))?;
                let mut imp = Importer::new();
                let mut n = 0;
                while let Some(r) = rd.next_record().map_err(|e| format!("{name}: {e:?}"))? {
                    n += usize::from(matches!(r, Record::Entry { .. }));
                    imp.import(r).map_err(|e| format!("{name}: {e:?}"))?;
                }
                n
            }
        };
        entries.push((name.to_string(), n));
        for t in c.req("order")?.split(',') {
            let i = t.strip_prefix('d').unwrap_or(t);
            if let Some(ms) = t.strip_prefix('+') {
                ms.parse::<u64>().map_err(|_| format!("{name}: bad order step {t}"))?;
            } else if i.parse::<usize>().ok().is_none_or(|i| i >= n) {
                return Err(format!("{name}: order step {t} names no entry"));
            }
        }
    }
    Ok(())
}
