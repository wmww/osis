//! `padme/`: Padmé lengths and unpad rejections (spec/wire.md §5). Hand-written; every case is
//! re-derived: `l` gives `padme`; `p` gives `padded`; `padded` with `reject: padding` must fail.

use crate::file::VecFile;
use crate::unhex;
use osis_crypto::{pad, padme, unpad};

pub fn check(f: &VecFile) -> Result<(), String> {
    for c in f.live() {
        let name = c.name();
        if let Some(l) = c.get("l") {
            let l: usize = l.parse().map_err(|e| format!("{name}: l: {e}"))?;
            let want: usize = c.req("padme")?.parse().map_err(|e| format!("{name}: padme: {e}"))?;
            if padme(l) != want {
                return Err(format!("{name}: padme({l}) = {}, want {want}", padme(l)));
            }
        } else if let Some(p) = c.get("p") {
            let p = unhex(p)?;
            let want = unhex(c.req("padded")?)?;
            if pad(&p) != want || unpad(&want) != Ok(&p[..]) {
                return Err(format!("{name}: pad/unpad mismatch"));
            }
        } else {
            let padded = unhex(c.req("padded")?)?;
            if c.req("reject")? != "padding" || unpad(&padded).is_ok() {
                return Err(format!("{name}: expected rejection `padding`"));
            }
        }
    }
    Ok(())
}
