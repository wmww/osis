//! Large values (notes/api.md Large values; spec/data-model.md §6): a string or blob read as a
//! stream (`Read + Seek`, chunks fetched one at a time under the database lock, memory one chunk
//! plus the tree path), its payload length, and `set_stream` writes. A seek fetches nothing; the
//! next read fetches only the tree path to the chunk holding the position (tree nodes carry
//! lengths, spec/wire.md §6).

use crate::error::{Error, Result};
use crate::handle::Osis;
use crate::read::{AspectRef, PathRef, ak_of};
use crate::write::{AspectWrite, PathWrite};
use osis_core::{Link, Tid, Value};
use osis_schema::{AspectKey, Path, Type, type_at};
use std::io::{Read, Seek, SeekFrom};

/// The payload of a string or blob position, read lazily.
pub struct ValueStream {
    db: Osis,
    tid: Tid,
    src: Src,
    /// Payload length in bytes.
    len: u64,
    /// Payload bytes delivered (or skipped) so far.
    pos: u64,
}

enum Src {
    Inline(Vec<u8>),
    /// `buf[at..]`: the unread rest of the current chunk, `buf` starting at canonical byte
    /// `start`; `head`: bytes of the string head.
    Tree { reader: Box<osis_label::TreeReader>, buf: Vec<u8>, start: u64, at: usize, head: u64 },
}

impl std::fmt::Debug for ValueStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ValueStream({} of {} bytes)", self.pos, self.len)
    }
}

/// The length a canonical CBOR byte or text string head declares, with the head's size.
fn string_head(b: &[u8]) -> Option<(u64, usize)> {
    let first = *b.first()?;
    if !matches!(first >> 5, 2 | 3) {
        return None;
    }
    let info = first & 31;
    let n = match info {
        0..=23 => return Some((u64::from(info), 1)),
        24 => 1,
        25 => 2,
        26 => 4,
        27 => 8,
        _ => return None,
    };
    let bytes = b.get(1..1 + n)?;
    Some((bytes.iter().fold(0u64, |acc, x| (acc << 8) | u64::from(*x)), 1 + n))
}

fn not_string() -> Error {
    Error::Invalid("not a string or blob".into())
}

fn tree_reader(link: Link) -> osis_label::TreeReader {
    osis_label::TreeReader::new(link, osis_label::LargeParams::FORMAT.chunk.min, usize::MAX)
}

impl ValueStream {
    fn open(db: &Osis, tid: Tid, v: Value) -> Result<ValueStream> {
        match v {
            Value::Str(s) => Ok(ValueStream { db: db.clone(), tid, len: s.len() as u64, src: Src::Inline(s.into_bytes()), pos: 0 }),
            Value::Bytes(b) => Ok(ValueStream { db: db.clone(), tid, len: b.len() as u64, src: Src::Inline(b), pos: 0 }),
            Value::Link(link) => {
                let mut reader = Box::new(tree_reader(link));
                let mut first = Vec::new();
                let (len, head) = loop {
                    if let Some(h) = string_head(&first) {
                        break h;
                    }
                    if first.len() > 9 {
                        return Err(not_string());
                    }
                    match db.engine(|e| e.next_chunk(&tid, &mut reader))? {
                        Some(c) => first.extend(c),
                        None => return Err(not_string()),
                    }
                };
                let src = Src::Tree { reader, buf: first, start: 0, at: head, head: head as u64 };
                Ok(ValueStream { db: db.clone(), tid, len, src, pos: 0 })
            }
            _ => Err(not_string()),
        }
    }

    /// Payload length in bytes.
    pub fn len(&self) -> u64 {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    fn read_some(&mut self, out: &mut [u8]) -> Result<usize> {
        let left = usize::try_from(self.len.saturating_sub(self.pos)).unwrap_or(usize::MAX);
        let want = out.len().min(left);
        if want == 0 {
            return Ok(0);
        }
        let tid = self.tid;
        let n = match &mut self.src {
            Src::Inline(b) => {
                let start = usize::try_from(self.pos).unwrap_or(usize::MAX);
                let piece = b.get(start..start.saturating_add(want)).unwrap_or_default();
                out.get_mut(..piece.len()).unwrap_or_default().copy_from_slice(piece);
                piece.len()
            }
            Src::Tree { reader, buf, start, at, .. } => {
                while *at >= buf.len() {
                    match self.db.engine(|e| e.next_chunk(&tid, reader))? {
                        Some(c) => {
                            *start += buf.len() as u64;
                            *buf = c;
                            *at = 0;
                        }
                        None => return Err(Error::Storage("large value shorter than its head".into())),
                    }
                }
                let piece = buf.get(*at..).unwrap_or_default();
                let n = piece.len().min(want);
                out.get_mut(..n).unwrap_or_default().copy_from_slice(piece.get(..n).unwrap_or_default());
                *at += n;
                n
            }
        };
        self.pos += n as u64;
        Ok(n)
    }
}

fn io(e: Error) -> std::io::Error {
    std::io::Error::other(e)
}

impl Read for ValueStream {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        self.read_some(out).map_err(io)
    }
}

impl Seek for ValueStream {
    fn seek(&mut self, to: SeekFrom) -> std::io::Result<u64> {
        let target = match to {
            SeekFrom::Start(n) => Some(n),
            SeekFrom::End(d) => self.len.checked_add_signed(d),
            SeekFrom::Current(d) => self.pos.checked_add_signed(d),
        }
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "seek before the start"))?;
        let target = target.min(self.len);
        if let Src::Tree { reader, buf, start, at, head } = &mut self.src {
            let to = head.saturating_add(target);
            // inside the chunk held: just move; else restart the tree walk there
            if (*start..=*start + buf.len() as u64).contains(&to) {
                *at = (to - *start) as usize;
            } else {
                reader.seek(to);
                buf.clear();
                *start = to;
                *at = 0;
            }
        }
        self.pos = target;
        Ok(self.pos)
    }
}

impl Osis {
    /// The stored value at `path` of an aspect, links unmaterialized.
    fn raw_at<K: AspectKey>(&self, tid: Tid, key: &K, path: &Path) -> Result<Option<(Tid, Value)>> {
        let ak = ak_of(key)?;
        self.read(|r| {
            let tid = r.resolve(tid);
            let Some(v) = r.raw_value(tid, &ak)? else { return Ok(None) };
            Ok(osis_schema::value_at(&v, path).cloned().map(|x| (tid, x)))
        })
    }
}

impl<K: AspectKey> AspectRef<'_, K> {
    /// The aspect's string or blob payload as a stream (`Read + Seek`; above the
    /// materialization bound too). `None` when absent.
    pub fn stream(&self) -> Result<Option<ValueStream>> {
        self.path(Path::root()).stream()
    }

    /// The payload length in bytes of a string or blob aspect without materializing it.
    pub fn len(&self) -> Result<Option<u64>> {
        Ok(self.stream()?.map(|s| s.len()))
    }
}

impl<K: AspectKey> PathRef<'_, '_, K> {
    /// The string or blob at the path as a stream. `None` when absent.
    pub fn stream(&self) -> Result<Option<ValueStream>> {
        let (db, tid, key, path) = self.parts();
        match db.raw_at(tid, key, path)? {
            Some((tid, v)) => Ok(Some(ValueStream::open(db, tid, v)?)),
            None => Ok(None),
        }
    }

    /// The payload length in bytes of the string or blob at the path.
    pub fn len(&self) -> Result<Option<u64>> {
        Ok(self.stream()?.map(|s| s.len()))
    }
}

impl<K: AspectKey> AspectWrite<'_, '_, K> {
    /// Sets a string or blob aspect from a reader (a string must be UTF-8).
    pub fn set_stream(&mut self, r: impl Read) -> Result<()> {
        self.path(Path::root()).set_stream(r)
    }
}

impl<K: AspectKey> PathWrite<'_, '_, '_, K> {
    /// Sets the string or blob at the path from a reader: a string when the key's schema says
    /// so (UTF-8 checked), else a blob. The value is read whole before the commit for now
    /// (issues/api-deferred.md).
    pub fn set_stream(&mut self, mut r: impl Read) -> Result<()> {
        let mut b = Vec::new();
        r.read_to_end(&mut b).map_err(|e| Error::Invalid(format!("reading the value: {e}")))?;
        let text = match self.position_type()? {
            Some(Type::String | Type::Text) => true,
            Some(Type::Named(n, _)) if n == "markdown" => true,
            _ => false,
        };
        let v = if text { Value::Str(String::from_utf8(b).map_err(|_| Error::Invalid("not UTF-8".into()))?) } else { Value::Bytes(b) };
        self.set_value(v)
    }
}

/// The schema type at a path of a key, if typed.
pub(crate) fn type_of<K: AspectKey>(key: &K, path: &Path) -> Result<Option<Type>> {
    let (Some(s), Some(ty)) = (key.schema(), key.ty()) else { return Ok(None) };
    Ok(Some(type_at(s, ty, path)?.0))
}
