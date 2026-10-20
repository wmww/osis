//! A local walk through the chat pattern: one device, no servers, two personas of one person.
#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used)]

fn main() {
    let (db, _) = osis::Osis::create(osis::Config::memory()).unwrap();
    let (c, me) = chat::new_chat(&db, "Lunch", "ann").unwrap();
    let alt = chat::persona(&db, c, "ann (work)").unwrap();
    let hi = chat::send(&db, me, "where to?", None).unwrap();
    chat::send(&db, alt, "the usual", Some(std::time::Duration::from_secs(60))).unwrap();
    chat::react(&db, alt, hi, "👍").unwrap();
    chat::mark_read(&db, me, hi).unwrap();
    for m in chat::timeline(&db, c).unwrap() {
        println!("{}: {}", m.nick, m.text);
    }
    println!("reactions to the first: {:?}", chat::reactions(&db, c, hi).unwrap());
}
