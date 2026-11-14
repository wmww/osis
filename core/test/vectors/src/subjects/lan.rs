//! `lan/`: a LAN announcement datagram (spec/sync-transport.md §4). Generated: transport key
//! `0d`, port 47381.

use super::{case, generated_header};
use crate::file::VecFile;
use crate::hex;
use osis_transport::lan::Announce;

const SPEC: &str = "spec/sync-transport.md §4";

pub fn announce() -> VecFile {
    let a = Announce { key: [0x0d; 32], port: 47_381 };
    let datagram = a.encode();
    assert_eq!(Announce::decode(&datagram), Some(a));
    let cases = vec![case("announce", SPEC).with("key", hex(&a.key)).with("port", a.port.to_string()).with("datagram", hex(&datagram))];
    VecFile { header: generated_header("lan", SPEC), cases }
}
