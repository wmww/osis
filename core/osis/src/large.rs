//! Large values (notes/api.md Large values; spec/data-model.md §6): a string or blob read as a
//! stream (`Read + Seek`, chunks fetched one at a time under the node lock, memory one chunk
//! plus the tree path), its payload length, and `set_stream` writes. A seek fetches nothing; the
//! next read fetches only the tree path to the chunk holding the position (tree nodes carry
//! lengths, spec/wire.md §6).

use crate::error::{Error, Result};
use crate::handle::ReadOnly;
use crate::read::{PathRef, ak_of};
use crate::write::PathWrite;
use osis_base::{Link, Tid, Value};
use osis_schema::{AspectKey, ValueKey};
use osis_schema::{Path, Type, type_at};
use std::io::{Read, Seek, SeekFrom};

/// The payload of a string or blob position, read lazily.
pub struct ValueStream {
    db: ReadOnly,
    tid: Tid,
    src: Src,
    /// Payload length in bytes.
    len: u64,
    /// Payload bytes delivered (or skipped) so far.
    pos: u64,
    /// Chunks fetched from the tree, and the most bytes held at once (`internals::stream_work`).
    chunks: u64,
    held: usize,
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

fn not_string() -> Error {
    Error::Invalid("not a string or blob".into())
}

fn tree_reader(link: Link) -> osis_label::TreeReader {
    osis_label::TreeReader::new(link, osis_label::LargeParams::FORMAT.chunk.min, usize::MAX)
}

impl ValueStream {
    fn open(db: &ReadOnly, tid: Tid, v: Value) -> Result<ValueStream> {
        match v {
            Value::Str(s) => Ok(ValueStream { db: db.clone(), tid, len: s.len() as u64, held: s.len(), src: Src::Inline(s.into_bytes()), pos: 0, chunks: 0 }),
            Value::Bytes(b) => Ok(ValueStream { db: db.clone(), tid, len: b.len() as u64, held: b.len(), src: Src::Inline(b), pos: 0, chunks: 0 }),
            Value::Link(link) => {
                let mut reader = Box::new(tree_reader(*link));
                let (mut first, mut chunks) = (Vec::new(), 0);
                let (len, head) = loop {
                    if let Some((_, len, n)) = osis_label::string_head(&first).map_err(|_| not_string())? {
                        break (len, n);
                    }
                    match db.engine(|e| e.next_chunk(&tid, &mut reader))? {
                        Some(c) => first.extend(c),
                        None => return Err(not_string()),
                    }
                    chunks += 1;
                };
                let held = first.len() + reader.path_links() * std::mem::size_of::<Link>();
                let src = Src::Tree { reader, buf: first, start: 0, at: head, head: head as u64 };
                Ok(ValueStream { db: db.clone(), tid, len, src, pos: 0, chunks, held })
            }
            _ => Err(not_string()),
        }
    }

    /// Payload length in bytes, known without reading the value.
    pub fn len(&self) -> u64 {
        self.len
    }

    /// Whether the value is empty.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Chunks fetched so far, and the most bytes of chunk and tree path held at once.
    pub(crate) fn work(&self) -> (u64, usize) {
        (self.chunks, self.held)
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
                            self.chunks += 1;
                            self.held = self.held.max(buf.len() + reader.path_links() * std::mem::size_of::<Link>());
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

impl ReadOnly {
    /// The stored value at `path` of an aspect, links unmaterialized.
    fn raw_at<K: AspectKey>(&self, tid: Tid, key: &K, path: &Path) -> Result<Option<(Tid, Value)>> {
        let ak = ak_of(key)?;
        self.read_local(|r| {
            let (tid, Some(v)) = r.raw(tid, &ak)? else { return Ok(None) };
            Ok(osis_schema::value_at(&v, path).cloned().map(|x| (tid, x)))
        })
    }
}

impl<K: ValueKey, H: std::borrow::Borrow<ReadOnly>> PathRef<'_, '_, K, H> {
    /// The string or blob here as a stream (`Read + Seek`), of any size. `None` when absent.
    pub fn stream(&self) -> Result<Option<ValueStream>> {
        let (db, tid, key, path) = self.read_parts();
        if db.tracking.is_some() {
            // the link, not the bytes: a change of the value is a new link
            let (ak, at) = (ak_of(key)?, path.clone());
            let ak2 = ak.clone();
            db.read_value(tid, &ak, format!("raw {}", crate::read::value_key(tid, &ak, path)), crate::watch::ReadAt::new(move |r| Ok(r.raw(tid, &ak2)?.1.and_then(|v| osis_schema::value_at(&v, &at).cloned()))))?;
        }
        match db.raw_at(tid, key, path)? {
            Some((tid, v)) => Ok(Some(ValueStream::open(db, tid, v)?)),
            None => Ok(None),
        }
    }
}

impl<K: ValueKey> PathWrite<'_, '_, '_, K> {
    /// Sets the string or blob here from a reader: a string when the key's schema says
    /// so (UTF-8 checked), else a blob. The value is read whole before the commit for now.
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
