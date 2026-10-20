//! `Backend`: transactional ordered KV of opaque bytes plus a blob area (notes/architecture.md §2).
//! Holds ciphertext only; the store above never hands it plaintext (notes/local-store.md).

use osis_core::{BlobId, Classified, ErrorClass};

/// A backend failure. Always Local (notes/architecture.md §3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BackendError {
    /// Underlying storage failed.
    Io(String),
    /// Injected by a `Faults` plan (tests, simulator).
    Fault,
    /// The simulated device crashed; nothing more is written until reopened.
    Crashed,
}

osis_core::impl_error!(BackendError {
    Io(m) => ("storage: {m}"),
    Fault => ("injected storage fault"),
    Crashed => ("storage crashed"),
});

impl Classified for BackendError {
    fn class(&self) -> ErrorClass {
        ErrorClass::Local
    }
}

/// A key and its value.
pub type KeyValue = (Vec<u8>, Vec<u8>);

/// One write of a batch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Op {
    Put(Vec<u8>, Vec<u8>),
    Delete(Vec<u8>),
    PutBlob(BlobId, Vec<u8>),
    DeleteBlob(BlobId),
}

/// Writes applied all-or-nothing and durably by `Backend::commit`, in order.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WriteBatch {
    pub ops: Vec<Op>,
}

impl WriteBatch {
    pub fn new() -> WriteBatch {
        WriteBatch::default()
    }
    pub fn put(&mut self, key: Vec<u8>, value: Vec<u8>) {
        self.ops.push(Op::Put(key, value));
    }
    pub fn delete(&mut self, key: Vec<u8>) {
        self.ops.push(Op::Delete(key));
    }
    pub fn put_blob(&mut self, id: BlobId, bytes: Vec<u8>) {
        self.ops.push(Op::PutBlob(id, bytes));
    }
    pub fn delete_blob(&mut self, id: BlobId) {
        self.ops.push(Op::DeleteBlob(id));
    }
    pub fn is_empty(&self) -> bool {
        self.ops.is_empty()
    }
    /// Payload bytes, for spill decisions.
    pub fn bytes(&self) -> usize {
        self.ops
            .iter()
            .map(|o| match o {
                Op::Put(k, v) => k.len() + v.len(),
                Op::Delete(k) => k.len(),
                Op::PutBlob(_, b) => 32 + b.len(),
                Op::DeleteBlob(_) => 32,
            })
            .sum()
    }
}

/// Transactional ordered KV with a blob area. Reads see the last committed batch (one handle,
/// one writer: `&mut self` commits exclude reads, so every read is a snapshot).
pub trait Backend: Send {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, BackendError>;
    /// Up to `limit` pairs with `start <= key < end` (`None`: unbounded), ascending.
    fn scan(&self, start: &[u8], end: Option<&[u8]>, limit: usize) -> Result<Vec<KeyValue>, BackendError>;
    /// Applies `batch` atomically; durable when it returns `Ok`.
    fn commit(&mut self, batch: WriteBatch) -> Result<(), BackendError>;
    fn get_blob(&self, id: &BlobId) -> Result<Option<Vec<u8>>, BackendError>;
    /// Bytes `offset..offset+len` of a blob (clipped at its end); `None` if absent.
    fn read_blob(&self, id: &BlobId, offset: u64, len: usize) -> Result<Option<Vec<u8>>, BackendError>;
    fn blob_len(&self, id: &BlobId) -> Result<Option<u64>, BackendError>;

    /// Up to `limit` pairs whose key starts with `prefix`.
    fn scan_prefix(&self, prefix: &[u8], limit: usize) -> Result<Vec<KeyValue>, BackendError> {
        let end = prefix_end(prefix);
        self.scan(prefix, end.as_deref(), limit)
    }
}

/// Options creating a file readable by its owner only (a store file, the root).
#[cfg(feature = "file-backend")]
pub(crate) fn owner_only() -> std::fs::OpenOptions {
    let mut o = std::fs::OpenOptions::new();
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut o, 0o600);
    o
}

/// Makes an existing store file (0600) or directory (0700) readable by its owner only, whatever
/// mode it was created with (a store made before files were created owner-only). No-op off unix.
#[cfg(feature = "file-backend")]
pub fn restrict_to_owner(path: &std::path::Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = if std::fs::metadata(path)?.is_dir() { 0o700 } else { 0o600 };
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

/// The least key greater than every key starting with `prefix`; `None` if there is none.
pub fn prefix_end(prefix: &[u8]) -> Option<Vec<u8>> {
    let mut end = prefix.to_vec();
    while let Some(last) = end.pop() {
        if last < 0xff {
            end.push(last + 1);
            return Some(end);
        }
    }
    None
}

/// Clips `offset..offset+len` to a blob of `blob.len()` bytes.
pub(crate) fn blob_slice(blob: &[u8], offset: u64, len: usize) -> Vec<u8> {
    let start = usize::try_from(offset).unwrap_or(usize::MAX).min(blob.len());
    let end = start.saturating_add(len).min(blob.len());
    blob.get(start..end).map(<[u8]>::to_vec).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    // spec: none (backend helper)
    #[test]
    fn prefix_end_cases() {
        assert_eq!(prefix_end(b"ab"), Some(b"ac".to_vec()));
        assert_eq!(prefix_end(&[1, 0xff]), Some(vec![2]));
        assert_eq!(prefix_end(&[0xff, 0xff]), None);
        assert_eq!(prefix_end(b""), None);
        assert_eq!(blob_slice(b"hello", 3, 10), b"lo");
        assert_eq!(blob_slice(b"hello", 9, 1), b"");
    }
}
