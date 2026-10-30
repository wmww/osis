//! File bundles (spec/wire.md §12, spec/sync.md §11): `osisbndl`, then length-framed canonical
//! CBOR records. `BundleWriter` streams records out; `BundleReader` streams them in;
//! `Importer` verifies paths, stamps and blob IDs as a server does and yields the events a
//! peer's log would.

use crate::auth::verify_stamp;
use crate::cbor::{get_bytes, get_opt, get_uint, uint};
use crate::blob::{blob_id, check_size};
use crate::labels::parse_step;
use crate::step::{ClaimSet, OBJECT_LIMITS, Step, verify_path};
use crate::Error;
use osis_base::cbor::{decode, encode};
use osis_base::format::MAX_MESSAGE;
use osis_base::{BlobId, LabelId, Value, WallMs};
use osis_crypto::{Signature, WRAP_LEN};
use std::collections::{HashMap, HashSet};
use std::io::{Read, Write};

pub const MAGIC: &[u8; 8] = b"osisbndl";
const FORMAT: u64 = 1;

/// One bundle record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Record {
    /// `[1, label_id, [[step, Opt(claim_set)]+]]`: the path from the genesis step to the head.
    Path { label: LabelId, steps: Vec<(Step, Option<ClaimSet>)> },
    /// `[2, blob]`: before the first entry naming it, once per bundle.
    Blob(Vec<u8>),
    /// `[3, label_id, blob_id, wrap, Opt(stamp)]`; no stamp: deposited.
    Entry { label: LabelId, blob: BlobId, wrap: [u8; WRAP_LEN], stamp: Option<Signature> },
    /// `[4, label_id, blob_id]`.
    Delete { label: LabelId, blob: BlobId },
    /// `[5, label_id, blob_id, at]`.
    TimedDelete { label: LabelId, blob: BlobId, at: WallMs },
    /// A record of a kind this build does not know: skipped.
    Unknown(u64),
}

impl Record {
    /// `Unknown` has no encoding.
    pub fn to_value(&self) -> Result<Value, Error> {
        Ok(Value::List(match self {
            Record::Path { label, steps } => {
                let steps = steps.iter().map(|(s, c)| Value::List(vec![Value::bytes(&s.to_bytes()), Value::opt(c.as_ref().map(|c| Value::bytes(&c.to_bytes())))]));
                vec![Value::Int(1), Value::bytes(&label.0), Value::List(steps.collect())]
            }
            Record::Blob(b) => vec![Value::Int(2), Value::bytes(b)],
            Record::Entry { label, blob, wrap, stamp } => {
                vec![Value::Int(3), Value::bytes(&label.0), Value::bytes(&blob.0), Value::bytes(wrap), Value::opt(stamp.map(|s| Value::bytes(&s.0)))]
            }
            Record::Delete { label, blob } => vec![Value::Int(4), Value::bytes(&label.0), Value::bytes(&blob.0)],
            Record::TimedDelete { label, blob, at } => vec![Value::Int(5), Value::bytes(&label.0), Value::bytes(&blob.0), uint(at.0)?],
            Record::Unknown(_) => return Err(Error::Malformed("unknown record has no encoding")),
        }))
    }

    pub fn from_value(v: &Value) -> Result<Record, Error> {
        let Value::List(items) = v else { return Err(Error::Malformed("bundle record")) };
        let (kind, rest) = items.split_first().ok_or(Error::Malformed("bundle record"))?;
        let label = |v: &Value| get_bytes(v, "record label").map(LabelId);
        let blob = |v: &Value| get_bytes(v, "record blob id").map(BlobId);
        Ok(match (get_uint(kind, "record kind")?, rest) {
            (1, [l, Value::List(steps)]) => {
                if steps.is_empty() {
                    return Err(Error::Malformed("empty path"));
                }
                let steps = steps.iter().map(path_step).collect::<Result<_, _>>()?;
                Record::Path { label: label(l)?, steps }
            }
            (2, [Value::Bytes(b)]) => {
                check_size(b)?;
                Record::Blob(b.clone())
            }
            (3, [l, b, w, s]) => Record::Entry {
                label: label(l)?,
                blob: blob(b)?,
                wrap: get_bytes(w, "record wrap")?,
                stamp: get_opt(s, "record stamp")?.map(|s| get_bytes(s, "record stamp").map(Signature)).transpose()?,
            },
            (4, [l, b]) => Record::Delete { label: label(l)?, blob: blob(b)? },
            (5, [l, b, at]) => Record::TimedDelete { label: label(l)?, blob: blob(b)?, at: WallMs(get_uint(at, "record at")?) },
            (0..=5, _) => return Err(Error::Malformed("bundle record")),
            (k, _) => Record::Unknown(k),
        })
    }
}

/// `[step, Opt(claim_set)]`, each as its canonical bytes; the set must hash to the step's.
fn path_step(v: &Value) -> Result<(Step, Option<ClaimSet>), Error> {
    let Value::List(f) = v else { return Err(Error::Malformed("path step")) };
    let [Value::Bytes(s), c] = f.as_slice() else { return Err(Error::Malformed("path step")) };
    let claims = match get_opt(c, "path claim set")? {
        Some(Value::Bytes(c)) => Some(c.as_slice()),
        Some(_) => return Err(Error::Malformed("path claim set")),
        None => None,
    };
    parse_step(s, claims)
}

fn frame_out(w: &mut dyn Write, v: &Value) -> Result<(), Error> {
    let b = encode(v);
    if b.len() > MAX_MESSAGE {
        return Err(Error::TooLarge("bundle record above MAX_MESSAGE"));
    }
    let len = u32::try_from(b.len()).map_err(|_| Error::TooLarge("bundle record"))?;
    w.write_all(&len.to_be_bytes()).and_then(|()| w.write_all(&b)).map_err(|_| Error::Storage)
}

/// Writes a bundle: the magic and format record on creation, then records in order.
pub struct BundleWriter<W: Write> {
    w: W,
}

impl<W: Write> BundleWriter<W> {
    pub fn new(mut w: W) -> Result<BundleWriter<W>, Error> {
        w.write_all(MAGIC).map_err(|_| Error::Storage)?;
        frame_out(&mut w, &Value::List(vec![Value::Int(0), uint(FORMAT)?]))?;
        Ok(BundleWriter { w })
    }

    pub fn record(&mut self, r: &Record) -> Result<(), Error> {
        frame_out(&mut self.w, &r.to_value()?)
    }

    pub fn finish(mut self) -> Result<W, Error> {
        self.w.flush().map_err(|_| Error::Storage)?;
        Ok(self.w)
    }
}

/// Reads a bundle record by record. A truncated or malformed frame is bad input; the end of the
/// input at a frame boundary ends the bundle.
pub struct BundleReader<R: Read> {
    r: R,
}

impl<R: Read> BundleReader<R> {
    /// Checks the magic and the format record (another format parks).
    pub fn new(mut r: R) -> Result<BundleReader<R>, Error> {
        let mut magic = [0u8; 8];
        r.read_exact(&mut magic).map_err(|_| Error::Malformed("bundle magic"))?;
        if magic != *MAGIC {
            return Err(Error::Malformed("bundle magic"));
        }
        let mut br = BundleReader { r };
        let v = br.frame()?.ok_or(Error::Malformed("bundle without format record"))?;
        match &v {
            Value::List(items) => match items.as_slice() {
                [Value::Int(0), f] => match get_uint(f, "bundle format")? {
                    FORMAT => Ok(br),
                    n => Err(Error::UnknownFormat(n)),
                },
                _ => Err(Error::Malformed("bundle format record")),
            },
            _ => Err(Error::Malformed("bundle format record")),
        }
    }

    fn frame(&mut self) -> Result<Option<Value>, Error> {
        let mut len = [0u8; 4];
        let mut got = 0;
        while got < 4 {
            let rest = len.get_mut(got..).unwrap_or(&mut []);
            match self.r.read(rest) {
                Ok(0) if got == 0 => return Ok(None),
                Ok(0) => return Err(Error::Malformed("truncated frame")),
                Ok(n) => got += n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(_) => return Err(Error::Storage),
            }
        }
        let len = usize::try_from(u32::from_be_bytes(len)).map_err(|_| Error::Malformed("frame length"))?;
        if len == 0 || len > MAX_MESSAGE {
            return Err(Error::Malformed("frame length"));
        }
        let mut buf = Vec::new();
        let n = (&mut self.r).take(u64::try_from(len).unwrap_or(0)).read_to_end(&mut buf).map_err(|_| Error::Storage)?;
        if n != len {
            return Err(Error::Malformed("truncated frame"));
        }
        Ok(Some(decode(&buf, &OBJECT_LIMITS)?))
    }

    /// The next record, or `None` at the end.
    pub fn next_record(&mut self) -> Result<Option<Record>, Error> {
        match self.frame()? {
            None => Ok(None),
            Some(v) => {
                if let Value::List(items) = &v
                    && items.first() == Some(&Value::Int(0))
                {
                    return Err(Error::Malformed("second format record"));
                }
                Record::from_value(&v).map(Some)
            }
        }
    }
}

/// What an import yields: the events of a peer's log replayed without a cursor (spec/wire.md
/// §11.2 events), plus the blob bytes they name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BundleEvent {
    /// A verified registration path; its last step is the head.
    Path { label: LabelId, steps: Vec<(Step, Option<ClaimSet>)> },
    /// Blob bytes, ID checked by hashing.
    Blob { id: BlobId, blob: Vec<u8> },
    /// An entry; a stamp verified against the label's head write key; no stamp: deposited.
    Add { label: LabelId, blob: BlobId, wrap: [u8; WRAP_LEN], stamp: Option<Signature> },
    Deleted { label: LabelId, blob: BlobId },
    TimedDelete { label: LabelId, blob: BlobId, at: WallMs },
}

/// Verifies bundle records as a server does: paths step by step, stamps against the path's head,
/// entries only for blobs given earlier. Unknown records are skipped.
#[derive(Default)]
pub struct Importer {
    heads: HashMap<LabelId, Step>,
    blobs: HashSet<BlobId>,
}

impl Importer {
    pub fn new() -> Importer {
        Importer::default()
    }

    /// The head of a label's imported path.
    pub fn head(&self, label: &LabelId) -> Option<&Step> {
        self.heads.get(label)
    }

    pub fn import(&mut self, r: Record) -> Result<Option<BundleEvent>, Error> {
        Ok(Some(match r {
            Record::Path { label, steps } => {
                let path: Vec<Step> = steps.iter().map(|(s, _)| s.clone()).collect();
                verify_path(&label, &path)?;
                // Like a server: a later path must pass through the current head (extend it).
                if let Some(cur) = self.heads.get(&label) {
                    let id = cur.id();
                    if !path.iter().any(|s| s.id() == id) {
                        return Err(Error::Verify("path does not extend the head"));
                    }
                }
                if let Some(head) = path.last() {
                    self.heads.insert(label, head.clone());
                }
                BundleEvent::Path { label, steps }
            }
            Record::Blob(blob) => {
                let id = blob_id(&blob);
                self.blobs.insert(id);
                BundleEvent::Blob { id, blob }
            }
            Record::Entry { label, blob, wrap, stamp } => {
                if !self.blobs.contains(&blob) {
                    return Err(Error::Malformed("entry before its blob"));
                }
                if let Some(s) = &stamp {
                    let head = self.heads.get(&label).ok_or(Error::Malformed("stamped entry before its label's path"))?;
                    verify_stamp(&head.keys.write, &label, &blob, &wrap, s)?;
                }
                BundleEvent::Add { label, blob, wrap, stamp }
            }
            Record::Delete { label, blob } => BundleEvent::Deleted { label, blob },
            Record::TimedDelete { label, blob, at } => BundleEvent::TimedDelete { label, blob, at },
            Record::Unknown(_) => return Ok(None),
        }))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::auth::sign_stamp;
    use crate::blob::{Prefix, frame};
    use crate::step::tests::{Group, TG};
    use crate::step::{Parent, register};
    use osis_crypto::{Epoch, LabelRole, SeededRng, label_role_key, wrap};

    /// A bundle: one label path, two blobs (one under two labels), entries, a deletion and a
    /// timed deletion.
    pub(crate) fn sample(rng: &mut SeededRng) -> (Vec<Record>, Vec<u8>) {
        let (g, h) = (Group::new(10), Group::new(20));
        let e = Epoch::new(0, [0; 32]).unwrap();
        let (s0, c0) = register(Parent::Genesis(&g.delete(0)), g.keys(0), &[], (&TG, e, &g.read), rng).unwrap();
        let (t0, _) = register(Parent::Genesis(&h.delete(0)), h.keys(0), &[], (&TG, e, &h.read), rng).unwrap();
        let p = Prefix::new([1; 16], None, vec![]).unwrap();
        let (k1, b1) = frame(&p, b"one", rng).unwrap();
        let (_, b2) = frame(&p, b"two", rng).unwrap();
        let (i1, i2) = (blob_id(&b1), blob_id(&b2));
        let w1 = wrap(&g.read, &i1, &k1).unwrap();
        let w1h = wrap(&h.read, &i1, &k1).unwrap();
        let st = sign_stamp(&label_role_key(LabelRole::Write, &g.write, 0), &s0.label, &i1, &w1);
        let sth = sign_stamp(&label_role_key(LabelRole::Write, &h.write, 0), &t0.label, &i1, &w1h);
        let recs = vec![
            Record::Path { label: s0.label, steps: vec![(s0.clone(), Some(c0))] },
            Record::Path { label: t0.label, steps: vec![(t0.clone(), None)] },
            Record::Blob(b1),
            Record::Entry { label: s0.label, blob: i1, wrap: w1, stamp: Some(st) },
            Record::Entry { label: t0.label, blob: i1, wrap: w1h, stamp: Some(sth) },
            Record::Blob(b2),
            Record::Entry { label: s0.label, blob: i2, wrap: [7; WRAP_LEN], stamp: None },
            Record::Delete { label: s0.label, blob: BlobId([3; 32]) },
            Record::TimedDelete { label: s0.label, blob: i2, at: WallMs(1234) },
        ];
        let mut w = BundleWriter::new(Vec::new()).unwrap();
        for r in &recs {
            w.record(r).unwrap();
        }
        (recs, w.finish().unwrap())
    }

    // spec/wire.md §12: a bundle round trips record by record and imports as log events with
    // paths and stamps verified; unknown records are skipped.
    #[test]
    fn round_trip_and_import() {
        let mut rng = SeededRng::from_u64(1);
        let (recs, bytes) = sample(&mut rng);
        assert_eq!(&bytes[..8], MAGIC);
        let mut r = BundleReader::new(&bytes[..]).unwrap();
        let mut got = Vec::new();
        while let Some(x) = r.next_record().unwrap() {
            got.push(x);
        }
        assert_eq!(got, recs);
        let mut imp = Importer::new();
        let events: Vec<BundleEvent> = got.into_iter().filter_map(|x| imp.import(x).unwrap()).collect();
        assert_eq!(events.len(), recs.len());
        assert!(matches!(&events[3], BundleEvent::Add { stamp: Some(_), .. }));
        // An unknown kind is skipped.
        let mut w = BundleWriter::new(Vec::new()).unwrap();
        frame_out(&mut w.w, &Value::List(vec![Value::Int(9), Value::Int(0)])).unwrap();
        let b = w.finish().unwrap();
        let mut r = BundleReader::new(&b[..]).unwrap();
        assert_eq!(r.next_record().unwrap(), Some(Record::Unknown(9)));
        assert_eq!(imp.import(Record::Unknown(9)).unwrap(), None);
        assert_eq!(r.next_record().unwrap(), None);
    }

    // spec/sync.md §5, spec/wire.md §12: a later path record replaces the head only if it
    // extends it (no other branch, no rollback to an ancestor).
    #[test]
    fn path_extends_head() {
        let mut rng = SeededRng::from_u64(3);
        let g = Group::new(10);
        let e = Epoch::new(0, [0; 32]).unwrap();
        let (s0, _) = register(Parent::Genesis(&g.delete(0)), g.keys(0), &[], (&TG, e, &g.read), &mut rng).unwrap();
        let child = |p: &Step, rng: &mut SeededRng| register(Parent::Child { step: p, delete: &g.delete(0) }, p.keys, &[], (&TG, e, &g.read), rng).unwrap().0;
        let (a, b) = (child(&s0, &mut rng), child(&s0, &mut rng));
        let a2 = child(&a, &mut rng);
        let path = |steps: &[&Step]| Record::Path { label: s0.label, steps: steps.iter().map(|s| ((*s).clone(), None)).collect() };
        let mut imp = Importer::new();
        imp.import(path(&[&s0, &a])).unwrap();
        assert!(imp.import(path(&[&s0, &b])).is_err());
        assert!(imp.import(path(&[&s0])).is_err());
        assert_eq!(imp.head(&s0.label), Some(&a));
        imp.import(path(&[&s0, &a, &a2])).unwrap();
        assert_eq!(imp.head(&s0.label), Some(&a2));
    }

    // spec/wire.md §12, spec/sync.md §5: an altered stamp, an entry before its blob or path, a
    // bad magic, a truncated frame or another format are rejected.
    #[test]
    fn rejections() {
        let mut rng = SeededRng::from_u64(2);
        let (recs, bytes) = sample(&mut rng);
        let mut imp = Importer::new();
        assert!(imp.import(recs[3].clone()).is_err());
        imp.import(recs[2].clone()).unwrap();
        assert!(imp.import(recs[3].clone()).is_err());
        imp.import(recs[0].clone()).unwrap();
        let Record::Entry { label, blob, mut wrap, stamp } = recs[3].clone() else { panic!() };
        wrap[0] ^= 1;
        assert!(imp.import(Record::Entry { label, blob, wrap, stamp }).is_err());
        let mut bad = bytes.clone();
        bad[0] = b'x';
        assert!(BundleReader::new(&bad[..]).is_err());
        let mut r = BundleReader::new(&bytes[..bytes.len() - 1]).unwrap();
        let mut last = Ok(None);
        for _ in 0..recs.len() {
            last = r.next_record();
        }
        assert!(last.is_err());
        let mut w = Vec::from(&MAGIC[..]);
        frame_out(&mut w, &Value::List(vec![Value::Int(0), Value::Int(2)])).unwrap();
        assert_eq!(BundleReader::new(&w[..]).err(), Some(Error::UnknownFormat(2)));
        let mut w = Vec::from(&MAGIC[..]);
        w.extend([0, 0, 0, 0]);
        assert!(BundleReader::new(&w[..]).is_err());
    }
}
