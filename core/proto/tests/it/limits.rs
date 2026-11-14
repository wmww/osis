//! Decoder limits (spec/wire.md §13; spec/requirements.md: peer input never causes unbounded
//! allocation): what a peer's bytes can make a decoder build is bounded by those bytes and the
//! caps, and a claim of more is refused before anything is built. Checked by sizes: the workspace
//! forbids the unsafe code a counting allocator needs.

use osis_base::{Value, cbor};
use osis_proto::filter::encode_gcs;
use osis_proto::limits::{MAX_FILTER_ENTRIES, MAX_MESSAGE, TOP_BIT};
use osis_proto::{Error, FrameDecoder, Msg};

// spec/wire.md §11.1, §13 (frame `MAX_MESSAGE`): a length prefix claiming a whole frame buffers
// only the bytes that came; one claiming more is refused before its body
#[test]
fn a_claimed_frame_length_allocates_nothing_spec_wire_13() {
    let mut d = FrameDecoder::new();
    d.push(&(MAX_MESSAGE as u32).to_be_bytes());
    d.push(&[0x80; 100]);
    assert_eq!(d.next_frame(), Ok(None));
    assert_eq!(d.pending(), 104);
    let mut d = FrameDecoder::new();
    d.push(&(MAX_MESSAGE as u32 + 1).to_be_bytes());
    assert!(d.next_frame().is_err());
}

// spec/wire.md §13 (no array or map longer than the bytes that remain): a head claiming 2^32
// items in a few bytes is refused, not allocated
#[test]
fn a_claimed_list_length_is_refused_spec_wire_13() {
    for head in [vec![0x9a, 0xff, 0xff, 0xff, 0xff], vec![0x9b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]] {
        let mut body = vec![0x84, 0x14, 0x01];
        body.extend(head);
        assert!(matches!(Msg::decode(&body).unwrap_err().error, Error::Cbor(_)));
    }
}

// spec/wire.md §13 (CBOR nesting at most 512 deep, values inside at most `MAX_VALUE_DEPTH`):
// nesting past 512 is refused by the CBOR reader; a Call argument past 64 by the message
#[test]
fn nesting_bounds_spec_wire_13() {
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

// spec/wire.md §13 (a message at most 2^20 CBOR data items in all): the items of the canonical
// bytes a byte string carries count too, so a claim set or entry box of one-byte items, a few
// bytes of the message's own items, is refused before it is built
#[test]
fn embedded_items_count_toward_the_message_spec_wire_13() {
    let ones = |n: usize, tail: &[u8]| {
        let mut b = vec![0x82, 0x9a];
        b.extend_from_slice(&(n as u32).to_be_bytes());
        b.extend(std::iter::repeat_n(0u8, n));
        b.extend_from_slice(tail);
        Value::Bytes(b)
    };
    let n = (1 << 20) + 1;
    let ms = osis_proto::examples::messages();
    let msg = |name: &str| ms.iter().find(|(m, _)| *m == name).map(|(_, m)| m.to_value()).unwrap();
    let Value::List(mut register) = msg("register") else { panic!() };
    register[4] = Value::List(vec![ones(n, &[0xa0])]);
    let Value::List(mut shared) = msg("shared with an entry grant") else { panic!() };
    let Value::List(items) = &mut shared[2] else { panic!() };
    let Value::List(item) = &mut items[0] else { panic!() };
    let Value::List(grant) = &mut item[2] else { panic!() };
    let Value::List(g) = &mut grant[0] else { panic!() };
    g[0] = Value::List(vec![ones(n, &[0x80])]);
    for body in [register, shared] {
        assert_eq!(Msg::decode(&cbor::encode(&Value::List(body))).unwrap_err().error, Error::Cap("message items"));
    }
}
