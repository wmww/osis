//! CBOR diagnostic notation (RFC 8949 §8) of definite-length bytes, for the `diag` field. Floats
//! print in shortest round-trip form with `.0` for integral values, or `NaN`, `Infinity`,
//! `-Infinity`; maps `{k: v, ...}`, arrays `[a, b]`, tags `n(content)`.

pub fn diag(b: &[u8]) -> Result<String, String> {
    let mut p = 0;
    let s = item(b, &mut p)?;
    if p != b.len() {
        return Err("trailing bytes".into());
    }
    Ok(s)
}

fn take<'a>(b: &'a [u8], p: &mut usize, n: usize) -> Result<&'a [u8], String> {
    let end = p.checked_add(n).ok_or("length overflow")?;
    let s = b.get(*p..end).ok_or("truncated")?;
    *p = end;
    Ok(s)
}

fn item(b: &[u8], p: &mut usize) -> Result<String, String> {
    let ib = take(b, p, 1)?[0];
    let (major, info) = (ib >> 5, ib & 31);
    if major == 7 {
        return match ib {
            0xf4 => Ok("false".into()),
            0xf5 => Ok("true".into()),
            0xfb => {
                let f = f64::from_bits(u64::from_be_bytes(take(b, p, 8)?.try_into().unwrap()));
                Ok(if f.is_nan() {
                    "NaN".into()
                } else if f.is_infinite() {
                    if f > 0.0 { "Infinity".into() } else { "-Infinity".into() }
                } else {
                    format!("{f:?}")
                })
            }
            _ => Err(format!("simple value {ib:#04x}")),
        };
    }
    let arg = match info {
        0..=23 => u64::from(info),
        24..=27 => take(b, p, 1 << (info - 24))?.iter().fold(0u64, |a, &x| (a << 8) | u64::from(x)),
        _ => return Err("indefinite or reserved".into()),
    };
    let len = || usize::try_from(arg).map_err(|e| e.to_string());
    Ok(match major {
        0 => arg.to_string(),
        1 => (-1 - i128::from(arg)).to_string(),
        2 => format!("h'{}'", crate::hex(take(b, p, len()?)?)),
        3 => text(std::str::from_utf8(take(b, p, len()?)?).map_err(|e| e.to_string())?),
        4 => format!("[{}]", (0..len()?).map(|_| item(b, p)).collect::<Result<Vec<_>, _>>()?.join(", ")),
        5 => {
            let kv = (0..len()?).map(|_| Ok(format!("{}: {}", item(b, p)?, item(b, p)?))).collect::<Result<Vec<_>, String>>()?;
            format!("{{{}}}", kv.join(", "))
        }
        _ => format!("{arg}({})", item(b, p)?),
    })
}

fn text(s: &str) -> String {
    let mut out = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if (c as u32) < 0x20 || c == '\u{7f}' => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}
