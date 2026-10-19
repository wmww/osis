//! Osis values (spec/data-model.md), ordered by canonical bytes.
use crate::cbor::{self, Item};
use std::cmp::Ordering;

pub const TAG_SET: u64 = 258;
pub const TAG_TID: u64 = 4001;
pub const TAG_ENUM: u64 = 4002;

#[derive(Clone, Debug)]
pub enum Value {
    Bool(bool),
    Int(i64),
    /// IEEE bit pattern; NaN canonicalized at construction.
    Float(u64),
    Str(String),
    Bytes(Vec<u8>),
    Tid([u8; 15]),
    List(Vec<Value>),
    /// Sorted by canonical key bytes, unique keys. Structs are maps with int keys.
    Map(Vec<(Value, Value)>),
    /// Sorted by canonical bytes, unique.
    Set(Vec<Value>),
    Enum(u64, Option<Box<Value>>),
}

impl Value {
    pub fn float(f: f64) -> Value {
        let f = if f.is_nan() { f64::NAN } else { f };
        Value::Float(f.to_bits())
    }
    pub fn map(mut kv: Vec<(Value, Value)>) -> Value {
        kv.sort_by(|a, b| a.0.cmp(&b.0));
        kv.dedup_by(|a, b| a.0 == b.0);
        Value::Map(kv)
    }
    pub fn set(mut v: Vec<Value>) -> Value {
        v.sort();
        v.dedup();
        Value::Set(v)
    }
    pub fn fields(kv: Vec<(u64, Value)>) -> Value {
        Value::map(kv.into_iter().map(|(k, v)| (Value::Int(k as i64), v)).collect())
    }
    pub fn to_item(&self) -> Item {
        match self {
            Value::Bool(b) => Item::Bool(*b),
            Value::Int(i) => Item::Int(*i),
            Value::Float(b) => Item::Float(*b),
            Value::Str(s) => Item::Text(s.clone()),
            Value::Bytes(b) => Item::Bytes(b.clone()),
            Value::Tid(t) => Item::Tag(TAG_TID, Box::new(Item::Bytes(t.to_vec()))),
            Value::List(l) => Item::Array(l.iter().map(|v| v.to_item()).collect()),
            Value::Map(m) => Item::Map(m.iter().map(|(k, v)| (k.to_item(), v.to_item())).collect()),
            Value::Set(s) => Item::Tag(TAG_SET, Box::new(Item::Array(s.iter().map(|v| v.to_item()).collect()))),
            Value::Enum(id, p) => {
                let mut a = vec![Item::Int(*id as i64)];
                if let Some(p) = p {
                    a.push(p.to_item());
                }
                Item::Tag(TAG_ENUM, Box::new(Item::Array(a)))
            }
        }
    }
    pub fn from_item(it: &Item) -> Result<Value, cbor::Error> {
        Ok(match it {
            Item::Bool(b) => Value::Bool(*b),
            Item::Int(i) => Value::Int(*i),
            Item::Float(b) => Value::Float(*b),
            Item::Text(s) => Value::Str(s.clone()),
            Item::Bytes(b) => Value::Bytes(b.clone()),
            Item::Array(a) => Value::List(a.iter().map(Value::from_item).collect::<Result<_, _>>()?),
            Item::Map(m) => {
                let kv: Vec<(Value, Value)> = m
                    .iter()
                    .map(|(k, v)| Ok((Value::from_item(k)?, Value::from_item(v)?)))
                    .collect::<Result<_, cbor::Error>>()?;
                // Decoder already enforced sorted unique keys on items; values' order is the same.
                Value::Map(kv)
            }
            Item::Tag(TAG_TID, b) => match &**b {
                Item::Bytes(x) if x.len() == 15 => Value::Tid(x[..].try_into().unwrap()),
                _ => return Err(cbor::Error::Bad("tid")),
            },
            Item::Tag(TAG_SET, b) => match &**b {
                Item::Array(a) => {
                    let v: Vec<Value> = a.iter().map(Value::from_item).collect::<Result<_, _>>()?;
                    if v.windows(2).any(|w| w[0] >= w[1]) {
                        return Err(cbor::Error::Bad("set order"));
                    }
                    Value::Set(v)
                }
                _ => return Err(cbor::Error::Bad("set")),
            },
            Item::Tag(TAG_ENUM, b) => match &**b {
                Item::Array(a) if a.len() == 1 || a.len() == 2 => {
                    let id = match &a[0] {
                        Item::Int(i) if *i >= 0 => *i as u64,
                        _ => return Err(cbor::Error::Bad("enum id")),
                    };
                    let p = a.get(1).map(Value::from_item).transpose()?.map(Box::new);
                    Value::Enum(id, p)
                }
                _ => return Err(cbor::Error::Bad("enum")),
            },
            Item::Tag(_, _) => return Err(cbor::Error::Bad("tag")),
        })
    }
    pub fn canonical(&self) -> Vec<u8> {
        cbor::encode(&self.to_item())
    }
}

impl PartialEq for Value {
    fn eq(&self, o: &Self) -> bool {
        self.canonical() == o.canonical()
    }
}
impl Eq for Value {}
impl Ord for Value {
    fn cmp(&self, o: &Self) -> Ordering {
        self.canonical().cmp(&o.canonical())
    }
}
impl PartialOrd for Value {
    fn partial_cmp(&self, o: &Self) -> Option<Ordering> {
        Some(self.cmp(o))
    }
}
