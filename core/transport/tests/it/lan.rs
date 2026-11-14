//! LAN discovery (`P2p::discover`) over LAN segments of the in-process NAT model: joins,
//! announcements, what a receiver dials, route ranks. spec/sync-transport.md §4.

use osis_transport::lan::{PORT, broadcast};
use osis_transport::*;
use std::future::{Future, poll_fn};
use std::net::IpAddr;
use std::task::Poll;

/// `f`'s output if it is ready at once.
async fn now_or_never<T>(f: impl Future<Output = T>) -> Option<T> {
    let mut f = std::pin::pin!(f);
    poll_fn(|cx| Poll::Ready(match f.as_mut().poll(cx) {
        Poll::Ready(v) => Some(v),
        Poll::Pending => None,
    }))
    .await
}

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

/// A host at `at` on LAN segment `seg`.
fn on_lan(net: &Net, name: &str, at: &str, seg: &str) -> MemUdp {
    let u = net.udp(name, ip(at), None);
    u.on_lan(seg, ip(at));
    u
}

fn cfg() -> LanConfig {
    LanConfig { to: vec![broadcast(PORT)], listen: vec!["peer://0.0.0.0:0".into()], ..LanConfig::default() }
}

/// A P2P transport on `udp` running discovery by `cfg()`.
fn node(udp: MemUdp) -> P2p<MemUdp> {
    P2p::new(udp).lan(cfg())
}

type D = Discovery<P2pConn<MemConn>>;
type Events = Vec<Found<P2pConn<MemConn>>>;

/// Runs everything to rest, then takes the events `d` has, without waiting.
fn drain(sched: &mut Sched, mut d: D) -> (D, Events) {
    sched.run();
    sched.block_on(async move {
        let mut out = Vec::new();
        while let Some(Some(f)) = now_or_never(d.next()).await {
            out.push(f);
        }
        (d, out)
    })
    .unwrap()
}

fn dials(found: &Events) -> Vec<Address> {
    found.iter().filter_map(|f| if let Found::Dial(a) = f { Some(a.clone()) } else { None }).collect()
}

/// Discovery started on each of `hosts` (all at once), run to rest.
fn start(sched: &mut Sched, hosts: Vec<P2p<MemUdp>>) -> Vec<D> {
    sched.block_on(async move {
        let mut out = Vec::new();
        for h in &hosts {
            out.push(h.discover().await.unwrap());
        }
        out
    })
    .unwrap()
}

// spec/sync-transport.md §4 (joining, dialing): each node on a segment hands up every other
// node's join once (repeats and its own announcements ignored), at the sender's address and
// announced port; a node on another segment hears nothing; a rejoin is a fresh key, which the
// others hand up again.
#[test]
fn joins_are_dialed_once_per_key() {
    let net = Net::new(0);
    let mut sched = Sched::new(0, Some(net.clone()));
    let hosts = vec![
        node(on_lan(&net, "a", "10.0.0.1", "home")),
        node(on_lan(&net, "b", "10.0.0.2", "home")),
        node(on_lan(&net, "c", "10.9.0.3", "away")),
    ];
    let mut ds = start(&mut sched, hosts).into_iter();
    let (da, db, dc) = (ds.next().unwrap(), ds.next().unwrap(), ds.next().unwrap());
    let (da, ea) = drain(&mut sched, da);
    let (db, eb) = drain(&mut sched, db);
    let (dc, ec) = drain(&mut sched, dc);
    let (to_b, to_a) = (dials(&ea), dials(&eb));
    assert_eq!(to_b.len(), 1, "{to_b:?}");
    assert_eq!(to_a.len(), 1, "{to_a:?}");
    assert!(to_b[0].url.starts_with("peer://10.0.0.2:") && to_a[0].url.starts_with("peer://10.0.0.1:"), "{to_b:?} {to_a:?}");
    assert_ne!(to_a[0].key, to_b[0].key);
    assert!(ec.is_empty(), "another segment hears nothing");
    db.rejoin();
    let (da, ea) = drain(&mut sched, da);
    let again = dials(&ea);
    assert_eq!(again.len(), 1, "{again:?}");
    assert_ne!(again[0].key, to_b[0].key, "a fresh key per join");
    assert!(again[0].url.starts_with("peer://10.0.0.2:"));
    drop((da, db, dc));
}

// spec/sync-transport.md §1 (route rank), §4: a connection to a LAN listener is rank 0 at both
// ends; the same node's dialable listener is rank 1.
#[test]
fn lan_connection_ranks_zero_at_both_ends() {
    let net = Net::new(1);
    let mut sched = Sched::new(1, Some(net.clone()));
    let (a, b) = (node(on_lan(&net, "a", "10.0.0.1", "home")), node(on_lan(&net, "b", "10.0.0.2", "home")));
    let mut ds = start(&mut sched, vec![a.clone(), b.clone()]).into_iter();
    let (da, db) = (ds.next().unwrap(), ds.next().unwrap());
    let (da, ea) = drain(&mut sched, da);
    let (db, _) = drain(&mut sched, db);
    let to_b = dials(&ea).pop().unwrap();
    let (a2, b2) = (a, b);
    let (c, dialable) = sched
        .block_on(async move {
            let c = a2.dial(&to_b).await.unwrap();
            let l = b2.listen(ListenConfig { url: "peer://10.0.0.2:7000".into(), secret: StaticSecret::from_bytes([5; 32]) }).await.unwrap();
            let d = a2.dial(&l.address()).await.unwrap();
            (c, (d.rank(), l))
        })
        .unwrap();
    assert_eq!(c.rank(), RANK_LAN);
    assert_eq!(dialable.0, RANK_DIRECT);
    let (db, eb) = drain(&mut sched, db);
    let served: Vec<_> = eb.iter().filter_map(|f| if let Found::Conn(c) = f { Some(c.rank()) } else { None }).collect();
    assert_eq!(served, vec![RANK_LAN], "the LAN listener's connection, handed up");
    drop((da, db));
}

// spec/sync-transport.md §1 (route rank), §4: an announcement of a key that is not a LAN
// listener's (a node announcing its dialable key at its dialable listener) cannot make a rank 0
// connection: the dialer ranks it 1, as the listener does.
#[test]
fn an_announced_dialable_key_ranks_one_at_both_ends() {
    let net = Net::new(2);
    let mut sched = Sched::new(2, Some(net.clone()));
    let bu = on_lan(&net, "b", "10.0.0.2", "home");
    let (a, b) = (node(on_lan(&net, "a", "10.0.0.1", "home")), node(bu.clone()));
    let mut ds = start(&mut sched, vec![a.clone()]).into_iter();
    let da = ds.next().unwrap();
    let (b2, l2) = (b, bu);
    let mut l = sched
        .block_on(async move {
            let l = b2.listen(ListenConfig { url: "peer://10.0.0.2:7000".into(), secret: StaticSecret::from_bytes([5; 32]) }).await.unwrap();
            let sock = osis_transport::p2p::Udp::lan(&l2, 0).await.unwrap();
            sock.announce(&lan::Announce { key: l.address().key, port: 7000 }, broadcast(PORT)).await.unwrap();
            l
        })
        .unwrap();
    let (da, ea) = drain(&mut sched, da);
    let to_b = dials(&ea);
    assert_eq!(to_b.len(), 1, "{to_b:?}");
    assert_eq!(to_b[0].url, "peer://10.0.0.2:7000");
    let (c, s) = sched
        .block_on(async move {
            let c = a.dial(&to_b[0]).await.unwrap();
            let s = l.accept().await.unwrap();
            (c.rank(), s.rank())
        })
        .unwrap();
    assert_eq!((c, s), (RANK_DIRECT, RANK_DIRECT));
    drop(da);
}

// spec/sync-transport.md §4 (dialing), spec/requirements.md (no unbounded work from peer input):
// a flood of announcements of distinct keys is handed up paced, and what a join remembers stays
// within `LanConfig::recent` however many keys come; a repeat within that span is not handed
// up again.
#[test]
fn a_flood_of_keys_is_bounded() {
    let c = cfg();
    let cap = c.recent();
    assert_eq!(cap, (c.repeats as usize + 1) * (c.gap_ms / c.pace_ms) as usize + 1);
    let mut j = lan::Joined::new(Some([0; 32]), cap);
    let from: std::net::SocketAddr = "10.0.0.5:47380".parse().unwrap();
    let key = |i: u32| {
        let mut k = [1u8; 32];
        k[..4].copy_from_slice(&i.to_be_bytes());
        k
    };
    for i in 0..u32::try_from(cap).unwrap() {
        assert!(j.heard(&lan::Announce { key: key(i), port: 9 }, from).is_some());
    }
    // every one of the last `cap` is still known
    for i in 0..u32::try_from(cap).unwrap() {
        assert!(j.heard(&lan::Announce { key: key(i), port: 9 }, from).is_none());
    }
    for i in 0..u32::try_from(10 * cap).unwrap() {
        j.heard(&lan::Announce { key: key(1_000_000 + i), port: 9 }, from);
    }
    // the newest `cap` are known, so it holds no more than `cap`: the one before them is forgotten
    let n = u32::try_from(10 * cap).unwrap();
    assert!(j.heard(&lan::Announce { key: key(1_000_000 + n - 1), port: 9 }, from).is_none());
    assert!(j.heard(&lan::Announce { key: key(1_000_000 + n - 1 - u32::try_from(cap).unwrap()), port: 9 }, from).is_some(), "past cap, forgotten");
    // pace 0 counts as 1 ms; nothing is repeated: one key
    assert_eq!(LanConfig { pace_ms: 0, repeats: 0, gap_ms: 0, ..cfg() }.recent(), 1);
}
