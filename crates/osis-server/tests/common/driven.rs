//! A scripted `ClientSession` over an osis-transport `Link` (driver tests, any transport).

use super::T0;
use osis_proto::*;
use osis_transport::Link;
use std::time::Duration;

pub const GUARD: Duration = Duration::from_secs(20);

pub struct Client {
    pub s: ClientSession,
    pub link: Link,
    pub events: Vec<ClientEvent>,
}

impl Client {
    /// Runs the handshake on `link` (a session dialed to the server under `key`).
    pub async fn start(link: Link, key: [u8; 32]) -> Client {
        assert_eq!(link.peer_key, key);
        let mut c = Client { s: ClientSession::new(ClientConfig { peer_static_key: key, challenge: [9; 32] }), link, events: vec![] };
        let out = c.s.handle(T0, ClientInput::Start);
        c.out(out);
        while !c.s.is_ready() {
            c.recv().await;
        }
        c.wait().await;
        c.events.clear();
        c
    }

    fn out(&mut self, out: Vec<ClientOutput>) {
        for o in out {
            match o {
                ClientOutput::Send(b) => assert!(self.link.tx.send(b, usize::MAX)),
                ClientOutput::Event(e) => self.events.push(e),
                _ => {}
            }
        }
    }

    async fn recv(&mut self) {
        let b = tokio::time::timeout(GUARD, self.link.rx.recv()).await.expect("no reply").expect("link closed");
        let out = self.s.handle(T0, ClientInput::Bytes(b));
        self.out(out);
    }

    async fn wait(&mut self) {
        while self.s.outstanding() > 0 {
            self.recv().await;
        }
    }

    pub async fn run(&mut self, cmd: Command) -> Vec<ClientEvent> {
        let out = self.s.handle(T0, ClientInput::Command(cmd));
        self.out(out);
        self.wait().await;
        std::mem::take(&mut self.events)
    }

    /// Waits for the next events (a push).
    pub async fn next(&mut self) -> Vec<ClientEvent> {
        while self.events.is_empty() {
            self.recv().await;
        }
        std::mem::take(&mut self.events)
    }

    /// Waits until pushes added `n` entries; returns their blob ids sorted.
    pub async fn pushed(&mut self, n: usize) -> Vec<osis_core::BlobId> {
        let mut got = vec![];
        while got.len() < n {
            got.extend(super::added(&super::events_of(&self.next().await).0));
        }
        super::sorted(got)
    }
}

pub struct Server {
    pub addr: osis_label::Address,
    pub control: tokio::sync::mpsc::Sender<osis_server::Control>,
    pub task: tokio::task::JoinHandle<osis_server::Hub<osis_store::MemoryBackend>>,
}

impl Server {
    /// Starts the driver on `transport` listening on `url` (static secret from `seed`), on a
    /// manual clock at `T0`.
    pub async fn start<T: osis_transport::Transport>(transport: T, url: &str, seed: u8, backend: osis_store::MemoryBackend, peers: Vec<osis_label::Address>) -> Server {
        use osis_transport::Listener;
        let clock = std::sync::Arc::new(osis_core::ManualClock::new(osis_core::WallMs(T0)));
        let store = osis_server::BackendStore::open(backend, clock.clone(), osis_server::Policy::default(), &mut osis_crypto::SeededRng::from_seed([seed; 32])).unwrap();
        let secret = osis_transport::StaticSecret::from_bytes([seed; 32]);
        let listener = transport.listen(osis_transport::ListenConfig { url: url.into(), secret: secret.clone() }).await.unwrap();
        let a = listener.address();
        let ep = osis_server::Endpoint { transport, listener, secret };
        let hub = osis_server::Hub::new(store, ep.key(), Box::new(osis_crypto::SeededRng::from_seed([1; 32])));
        let (control, rx) = tokio::sync::mpsc::channel(4);
        let task = tokio::spawn(osis_server::run(hub, ep, peers, clock, rx, std::sync::Arc::new(|m: &str| eprintln!("{m}"))));
        Server { addr: osis_label::Address { url: a.url, key: a.key }, control, task }
    }

    /// A client session dialed on `transport` with an ephemeral key.
    pub async fn client<T: osis_transport::Transport>(&self, transport: &T) -> Client {
        let target = osis_transport::Address { url: self.addr.url.clone(), key: self.addr.key };
        let link = osis_transport::link::dial(transport, &target, None, GUARD).await.unwrap();
        Client::start(link, self.addr.key).await
    }

    /// Shuts the driver down; returns its hub.
    pub async fn stop(self) -> osis_server::Hub<osis_store::MemoryBackend> {
        self.control.send(osis_server::Control::Shutdown).await.unwrap();
        self.task.await.unwrap()
    }
}
