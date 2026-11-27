//! Decoder limits (spec/wire.md §12; spec/requirements.md: peer input never causes unbounded
//! allocation): what a peer's bytes can make a decoder build is bounded by those bytes and the
//! caps, and a claim of more is refused before anything is built. Checked by sizes: the workspace
//! forbids the unsafe code a counting allocator needs.

use osis_base::{Value, cbor};
use osis_proto::filter::encode_gcs;
use osis_proto::limits::{MAX_FILTER_ENTRIES, MAX_MESSAGE, TOP_BIT};
use osis_proto::{Error, FrameDecoder, Msg};

// spec/wire.md §11.1, §12 (frame `MAX_MESSAGE`): a length prefix claiming a whole frame buffers
// only the bytes that came; one claiming more is refused before its body
#[test]
fn a_claimed_frame_length_allocates_nothing_spec_wire_12() {
    let mut d = FrameDecoder::new();
    d.push(&(MAX_MESSAGE as u32).to_be_bytes());
    d.push(&[0x80; 100]);
    assert_eq!(d.next_frame(), Ok(None));
    assert_eq!(d.pending(), 104);
    let mut d = FrameDecoder::new();
    d.push(&(MAX_MESSAGE as u32 + 1).to_be_bytes());
    assert!(d.next_frame().is_err());
}

// spec/wire.md §12 (no array or map longer than the bytes that remain): a head claiming 2^32
// items in a few bytes is refused, not allocated
#[test]
fn a_claimed_list_length_is_refused_spec_wire_12() {
    for head in [vec![0x9a, 0xff, 0xff, 0xff, 0xff], vec![0x9b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]] {
        let mut body = vec![0x84, 0x14, 0x01];
        body.extend(head);
        assert!(matches!(Msg::decode(&body).unwrap_err().error, Error::Cbor(_)));
    }
}

// spec/wire.md §12 (CBOR nesting at most 512 deep; values inside it at most `MAX_VALUE_DEPTH`):
// nesting past 512 is refused by the CBOR reader; a Call argument past 64 by the message
#[test]
fn nesting_bounds_spec_wire_12() {
    let nest = |n: usize| (0..n).fold(Value::uint(0), |v, _| Value::List(vec![v]));
    let call = |arg: Value| cbor::encode(&Value::List(vec![Value::uint(25), Value::uint(1), Value::uint(16_384), Value::uint(1), Value::List(vec![arg])]));
    assert!(Msg::decode(&call(nest(64))).is_ok());
    assert_eq!(Msg::decode(&call(nest(65))).unwrap_err().error, Error::Malformed("value too deep"));
    assert!(matches!(Msg::decode(&call(nest(600))).unwrap_err().error, Error::Cbor(_)));
}

// spec/wire.md §11.2 Beacons (a filter past 2^22 entries is refused): a page's values are
// counted as they are read, never held, and a page of more than `MAX_FILTER_ENTRIES` is refused;
// the decoded message holds the page's bytes only
#[test]
fn a_filter_page_is_counted_not_built_spec_wire_11_2() {
    let page = |values: &[u64]| Msg::Beacons { id: TOP_BIT | 1, generation: 1, base: None, f: 30, lo: 0, hi: 1 << 30, gcs: encode_gcs(values, 0), more: false };
    let n = MAX_FILTER_ENTRIES as usize;
    let at = page(&vec![7; n]);
    let body = at.encode();
    assert!(body.len() <= MAX_MESSAGE, "{}", body.len());
    let Ok(Msg::Beacons { gcs, .. }) = Msg::decode(&body) else { panic!() };
    assert!(gcs.len() < body.len());
    assert_eq!(Msg::decode(&page(&vec![7; n + 1]).encode()).unwrap_err().error, Error::Cap("filter entries"));
}

// spec/wire.md §11.2 (Per-message caps: Fetch 1024 IDs in all its groups): a Fetch's IDs count
// across its sync IDs' groups, so groups of the cap each are refused as one past it
#[test]
fn a_fetchs_ids_are_capped_across_its_groups_spec_wire_12() {
    let cap = osis_proto::limits::MAX_FETCH_IDS;
    // distinct blob IDs: group `g`'s `n` of them
    let group = |g: u8, n: usize| Value::List(vec![Value::Bytes(vec![g; 16]), Value::List((0..n).map(|i| Value::Bytes([[g; 2].as_slice(), &(i as u32).to_be_bytes(), &[0; 26]].concat())).collect())]);
    let fetch = |groups: Vec<Value>| cbor::encode(&Value::List(vec![Value::uint(19), Value::uint(u64::from(TOP_BIT) | 1), Value::uint(16_384), Value::List(groups)]));
    assert!(Msg::decode(&fetch(vec![group(1, cap / 2), group(2, cap / 2)])).is_ok(), "the cap in all");
    assert!(matches!(Msg::decode(&fetch(vec![group(1, cap / 2), group(2, cap / 2 + 1)])).unwrap_err().error, Error::Cap(_)), "one past it");
}
