//! `link/`: links and recovery cards (spec/wire.md §10). Generated: canonical bytes and text
//! forms, with and without peers; cap rejections.

use super::{case, generated_header, s32};
use crate::file::VecFile;
use crate::hex;
use osis_core::{LabelId, Tid, Value, encode};
use osis_label::{Address, Error, Peer, RecoveryCard, ShareLink};
use osis_schema::Codec;

const SPEC: &str = "spec/wire.md §10";

pub fn links() -> VecFile {
    let a = Address { url: "quic://server.example:4433".into(), key: [0x06; 32] };
    let link = ShareLink {
        seed: s32(0x03),
        target: Tid::from_bytes([0x01; 15]),
        k: Tid::from_bytes([0x02; 15]),
        k_label: LabelId([0x04; 16]),
        servers: vec![a.clone()],
        peers: vec![Peer { dialable: [0x07; 32], relays: vec!["https://relay.example".into()] }],
    };
    let mut bare = link.clone();
    bare.peers.clear();
    let card = RecoveryCard { seed: s32(0x04), person: Tid::from_bytes([0x05; 15]), home_label: LabelId([0x08; 16]), servers: vec![a.clone()] };
    let mut cases = Vec::new();
    for (name, l) in [("link with a peer", &link), ("link without peers", &bare)] {
        let t = l.to_text().unwrap();
        assert_eq!(&ShareLink::from_text(&t).unwrap(), l);
        cases.push(case(name, SPEC).with("bytes", hex(&l.to_bytes().unwrap())).with("text", t));
    }
    let t = card.to_text().unwrap();
    assert_eq!(RecoveryCard::from_text(&t).unwrap(), card);
    cases.push(case("recovery card", SPEC).with("bytes", hex(&card.to_bytes().unwrap())).with("text", t));

    let with = |i: usize, v: Value| {
        let Value::List(mut items) = link.to_value().unwrap() else { unreachable!() };
        items[i] = v;
        encode(&Value::List(items))
    };
    let nine = with(5, Value::List(vec![a.to_value(); 9]));
    let peer = Value::List(vec![Value::Bytes(vec![7; 32]), Value::List(vec![])]);
    let five = with(6, Value::List(vec![peer; 5]));
    let relays = with(6, Value::List(vec![Value::List(vec![Value::Bytes(vec![7; 32]), Value::List(vec![Value::Str("r".into()); 5])])]));
    let long = with(6, Value::List(vec![Value::List(vec![Value::Bytes(vec![7; 32]), Value::List(vec![Value::Str("r".repeat(257))])])]));
    for (name, b, rule) in [("nine addresses", nine, "link-cap"), ("five peers", five, "link-cap"), ("five relays", relays, "link-cap"), ("relay URL of 257 bytes", long, "link-cap")] {
        assert!(ShareLink::from_value(&osis_core::decode(&b, &osis_core::Limits::DEFAULT).unwrap()).is_err());
        cases.push(case(name, SPEC).with("bytes", hex(&b)).with("reject", rule));
    }
    let f2 = with(0, Value::Int(2));
    assert_eq!(ShareLink::from_value(&osis_core::decode(&f2, &osis_core::Limits::DEFAULT).unwrap()), Err(Error::UnknownFormat(2)));
    cases.push(case("link format 2", SPEC).with("bytes", hex(&f2)).with("parked", "format"));
    VecFile { header: generated_header("link", SPEC), cases }
}
