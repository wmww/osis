//! Minimal canonical CBOR subset (RFC 8949 §4.2.1): shortest heads, definite lengths,
//! sorted unique map keys, 8-byte floats only, no null/undefined. Strict decoder.
use std::cmp::Ordering;

#[derive(Clone, Debug, PartialEq)]
pub enum Item {
    Int(i64),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<Item>),
    /// Keys sorted by canonical encoding, unique.
    Map(Vec<(Item, Item)>),
    Tag(u64, Box<Item>),
    Bool(bool),
    Float(u64),
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Error {
    Truncated,
    Bad(&'static str),
    Trailing,
}

fn head(out: &mut Vec<u8>, major: u8, n: u64) {
    let m = major << 5;
    if n < 24 {
        out.push(m | n as u8);
    } else if n <= 0xff {
        out.push(m | 24);
        out.push(n as u8);
    } else if n <= 0xffff {
        out.push(m | 25);
        out.extend_from_slice(&(n as u16).to_be_bytes());
    } else if n <= 0xffff_ffff {
        out.push(m | 26);
        out.extend_from_slice(&(n as u32).to_be_bytes());
    } else {
        out.push(m | 27);
        out.extend_from_slice(&n.to_be_bytes());
    }
}

pub fn encode(it: &Item) -> Vec<u8> {
    let mut out = Vec::new();
    encode_into(it, &mut out);
    out
}

pub fn encode_into(it: &Item, out: &mut Vec<u8>) {
    match it {
        Item::Int(i) => {
            if *i >= 0 {
                head(out, 0, *i as u64)
            } else {
                head(out, 1, (-1 - *i) as u64)
            }
        }
        Item::Bytes(b) => {
            head(out, 2, b.len() as u64);
            out.extend_from_slice(b);
        }
        Item::Text(s) => {
            head(out, 3, s.len() as u64);
            out.extend_from_slice(s.as_bytes());
        }
        Item::Array(a) => {
            head(out, 4, a.len() as u64);
            for x in a {
                encode_into(x, out);
            }
        }
        Item::Map(m) => {
            head(out, 5, m.len() as u64);
            // Canonical order is enforced at construction (`sorted_map`); encode as given.
            for (k, v) in m {
                encode_into(k, out);
                encode_into(v, out);
            }
        }
        Item::Tag(t, x) => {
            head(out, 6, *t);
            encode_into(x, out);
        }
        Item::Bool(b) => out.push(if *b { 0xf5 } else { 0xf4 }),
        Item::Float(bits) => {
            out.push(0xfb);
            out.extend_from_slice(&bits.to_be_bytes());
        }
    }
}

/// Build a canonical map from unsorted pairs; duplicate keys keep the last.
pub fn sorted_map(mut kv: Vec<(Item, Item)>) -> Item {
    kv.sort_by(|a, b| cmp_items(&a.0, &b.0));
    kv.dedup_by(|a, b| a.0 == b.0);
    Item::Map(kv)
}

pub fn cmp_items(a: &Item, b: &Item) -> Ordering {
    encode(a).cmp(&encode(b))
}

pub fn decode(bytes: &[u8]) -> Result<Item, Error> {
    let mut d = Dec { b: bytes, p: 0, depth: 0 };
    let it = d.item()?;
    if d.p != bytes.len() {
        return Err(Error::Trailing);
    }
    Ok(it)
}

struct Dec<'a> {
    b: &'a [u8],
    p: usize,
    depth: u32,
}

impl<'a> Dec<'a> {
    fn byte(&mut self) -> Result<u8, Error> {
        let x = *self.b.get(self.p).ok_or(Error::Truncated)?;
        self.p += 1;
        Ok(x)
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        if self.b.len() - self.p < n {
            return Err(Error::Truncated);
        }
        let s = &self.b[self.p..self.p + n];
        self.p += n;
        Ok(s)
    }
    fn arg(&mut self, ai: u8) -> Result<u64, Error> {
        Ok(match ai {
            0..=23 => ai as u64,
            24 => {
                let v = self.byte()? as u64;
                if v < 24 {
                    return Err(Error::Bad("head"));
                }
                v
            }
            25 => {
                let v = u16::from_be_bytes(self.take(2)?.try_into().unwrap()) as u64;
                if v <= 0xff {
                    return Err(Error::Bad("head"));
                }
                v
            }
            26 => {
                let v = u32::from_be_bytes(self.take(4)?.try_into().unwrap()) as u64;
                if v <= 0xffff {
                    return Err(Error::Bad("head"));
                }
                v
            }
            27 => {
                let v = u64::from_be_bytes(self.take(8)?.try_into().unwrap());
                if v <= 0xffff_ffff {
                    return Err(Error::Bad("head"));
                }
                v
            }
            _ => return Err(Error::Bad("indefinite or reserved")),
        })
    }
    fn item(&mut self) -> Result<Item, Error> {
        self.depth += 1;
        if self.depth > 256 {
            return Err(Error::Bad("depth"));
        }
        let ib = self.byte()?;
        let (major, ai) = (ib >> 5, ib & 0x1f);
        let r = match major {
            0 => {
                let n = self.arg(ai)?;
                if n > i64::MAX as u64 {
                    return Err(Error::Bad("int range"));
                }
                Item::Int(n as i64)
            }
            1 => {
                let n = self.arg(ai)?;
                if n > i64::MAX as u64 {
                    return Err(Error::Bad("int range"));
                }
                Item::Int(-1 - n as i64)
            }
            2 => {
                let n = self.arg(ai)? as usize;
                Item::Bytes(self.take(n)?.to_vec())
            }
            3 => {
                let n = self.arg(ai)? as usize;
                let s = std::str::from_utf8(self.take(n)?).map_err(|_| Error::Bad("utf8"))?;
                Item::Text(s.to_string())
            }
            4 => {
                let n = self.arg(ai)?;
                if n > (self.b.len() - self.p) as u64 {
                    return Err(Error::Truncated);
                }
                let mut v = Vec::with_capacity(n as usize);
                for _ in 0..n {
                    v.push(self.item()?);
                }
                Item::Array(v)
            }
            5 => {
                let n = self.arg(ai)?;
                if n > (self.b.len() - self.p) as u64 {
                    return Err(Error::Truncated);
                }
                let mut v: Vec<(Item, Item)> = Vec::with_capacity(n as usize);
                let mut last: Option<Vec<u8>> = None;
                for _ in 0..n {
                    let start = self.p;
                    let k = self.item()?;
                    let kb = self.b[start..self.p].to_vec();
                    if let Some(l) = &last {
                        if kb <= *l {
                            return Err(Error::Bad("map order"));
                        }
                    }
                    last = Some(kb);
                    let val = self.item()?;
                    v.push((k, val));
                }
                Item::Map(v)
            }
            6 => {
                let t = self.arg(ai)?;
                Item::Tag(t, Box::new(self.item()?))
            }
            7 => match ai {
                20 => Item::Bool(false),
                21 => Item::Bool(true),
                27 => {
                    let bits = u64::from_be_bytes(self.take(8)?.try_into().unwrap());
                    let f = f64::from_bits(bits);
                    if f.is_nan() && bits != f64::NAN.to_bits() {
                        return Err(Error::Bad("nan"));
                    }
                    Item::Float(bits)
                }
                _ => return Err(Error::Bad("simple")),
            },
            _ => unreachable!(),
        };
        self.depth -= 1;
        Ok(r)
    }
}

/// Helpers for the wire layer.
impl Item {
    pub fn uint(&self) -> Result<u64, Error> {
        match self {
            Item::Int(i) if *i >= 0 => Ok(*i as u64),
            _ => Err(Error::Bad("uint expected")),
        }
    }
    pub fn array(&self) -> Result<&[Item], Error> {
        match self {
            Item::Array(a) => Ok(a),
            _ => Err(Error::Bad("array expected")),
        }
    }
    pub fn map(&self) -> Result<&[(Item, Item)], Error> {
        match self {
            Item::Map(m) => Ok(m),
            _ => Err(Error::Bad("map expected")),
        }
    }
}
