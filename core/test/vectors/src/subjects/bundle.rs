//! `bundle/`: a bundle file (spec/wire.md §12). Generated: two labels' paths (genesis steps of
//! group secrets read/write/admin `0a/0b/09` and `1a/1b/19`, deposit seed `0c`), two blobs (the
//! first under both labels), stamped and deposited entries, a deletion and a timed deletion.
//! Randomness per genesis step: `step-secret`, one `padding` key; per blob: its key.

use super::{FixedRng, case, generated_header, s32};
use crate::file::VecFile;
use crate::hex;
use osis_base::{BlobId, WallMs};
use osis_crypto::{Epoch, LabelRole, Secret32, WRAP_LEN, label_role_key, wrap};
use osis_label::{BundleReader, BundleWriter, Importer, Parent, Prefix, Record, StepKeys, frame, genesis_label, register, sign_stamp};

const SPEC: &str = "spec/wire.md §12";

fn genesis(read: &Secret32, write: &Secret32, admin: &Secret32, step: u8) -> (osis_label::Step, osis_label::ClaimSet) {
    let label = genesis_label(admin, 0);
    let keys = StepKeys::derive(read, write, admin, 0, &s32(0x0c), &label);
    let e = Epoch::new(0, [0; 32]).unwrap();
    let delete = label_role_key(LabelRole::Delete, admin, 0);
    register(Parent::Genesis(&delete), keys, &[], (&osis_base::Tid::from_bytes([0x07; 15]), e, read), &mut FixedRng::new(&[&[step; 32], &[step + 1; 32]])).unwrap()
}

pub fn bundle() -> VecFile {
    let (r0, w0, a0) = (s32(0x0a), s32(0x0b), s32(0x09));
    let (r1, w1, a1) = (s32(0x1a), s32(0x1b), s32(0x19));
    let (s0, c0) = genesis(&r0, &w0, &a0, 0x51);
    let (t0, _) = genesis(&r1, &w1, &a1, 0x53);
    let p = Prefix::new([0x55; 16], None, vec![]).unwrap();
    let (k1, b1) = frame(&p, b"one", &mut FixedRng::new(&[&[0x56; 32]])).unwrap();
    let (_, b2) = frame(&p, b"two", &mut FixedRng::new(&[&[0x57; 32]])).unwrap();
    let (i1, i2) = (osis_label::blob_id(&b1), osis_label::blob_id(&b2));
    let (w1s, w1t) = (wrap(&r0, &i1, &k1).unwrap(), wrap(&r1, &i1, &k1).unwrap());
    let st0 = sign_stamp(&label_role_key(LabelRole::Write, &w0, 0), &s0.label, &i1, &w1s);
    let st1 = sign_stamp(&label_role_key(LabelRole::Write, &w1, 0), &t0.label, &i1, &w1t);
    let recs = vec![
        Record::Path { label: s0.label, steps: vec![(s0.clone(), Some(c0))] },
        Record::Path { label: t0.label, steps: vec![(t0.clone(), None)] },
        Record::Blob(b1),
        Record::Entry { label: s0.label, blob: i1, wrap: w1s, stamp: Some(st0) },
        Record::Entry { label: t0.label, blob: i1, wrap: w1t, stamp: Some(st1) },
        Record::Blob(b2),
        Record::Entry { label: s0.label, blob: i2, wrap: [0x58; WRAP_LEN], stamp: None },
        Record::Delete { label: s0.label, blob: BlobId([0x59; 32]) },
        Record::TimedDelete { label: s0.label, blob: i2, at: WallMs(1_700_000_000_000) },
    ];
    let mut w = BundleWriter::new(Vec::new()).unwrap();
    for r in &recs {
        w.record(r).unwrap();
    }
    let bytes = w.finish().unwrap();
    let mut rd = BundleReader::new(&bytes[..]).unwrap();
    let mut imp = Importer::new();
    for r in &recs {
        let got = rd.next_record().unwrap().unwrap();
        assert_eq!(&got, r);
        imp.import(got).unwrap().unwrap();
    }
    assert_eq!(rd.next_record().unwrap(), None);
    let kinds = "path,path,blob,entry,entry,blob,entry,delete,timed-delete";
    let mut cases = vec![case("bundle", SPEC).with("records", kinds).with("bundle", hex(&bytes))];
    // An entry whose stamp does not verify against the head's write key.
    let Record::Entry { label, blob, wrap: w1, .. } = recs[3].clone() else { unreachable!() };
    let mut bad = BundleWriter::new(Vec::new()).unwrap();
    for r in [&recs[0], &recs[2]] {
        bad.record(r).unwrap();
    }
    bad.record(&Record::Entry { label, blob, wrap: w1, stamp: Some(st1) }).unwrap();
    let bad = bad.finish().unwrap();
    let mut rd = BundleReader::new(&bad[..]).unwrap();
    let mut imp = Importer::new();
    imp.import(rd.next_record().unwrap().unwrap()).unwrap();
    imp.import(rd.next_record().unwrap().unwrap()).unwrap();
    assert!(imp.import(rd.next_record().unwrap().unwrap()).is_err());
    cases.push(case("stamp of another label", SPEC).with("bundle", hex(&bad)).with("reject", "stamp"));
    VecFile { header: generated_header("bundle", SPEC), cases }
}
