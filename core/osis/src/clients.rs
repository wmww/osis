//! Thin clients of this node (notes/client-port.md §3): `clients.0^` on the node thing
//! (spec/data-model.md §9) lists a client actor per client with the hash of its bearer secret
//! and its end. The node mints the actor (an actor owned by the account, like a link's K) and
//! acts as it for the client's session (`port::serve`); what the client may read and write is
//! that actor's grants, nothing else. Any admin of the node thing may edit the registry.

use crate::error::{Error, Result};
use crate::handle::Osis;
use crate::port::method;
use osis_base::{Tid, Value, WallMs};
use osis_crdt::{Op, PathOp, PathSeg};
use osis_crypto::Secret32;
use osis_node::flows::{Demotion, PreSync};
use osis_schema::core_types as ct;
use osis_schema::{Codec, Path};

/// A thin client's bearer secret: shown once by `add_client` and `rotate_client_secret`; osis keeps
/// only its hash. Whoever holds it is the client. `Debug` is redacted; zeroized on drop.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientSecret(pub(crate) Secret32);

impl ClientSecret {
    fn generate() -> ClientSecret {
        ClientSecret(Secret32::random(&mut osis_crypto::OsRng))
    }

    pub fn from_bytes(b: [u8; 32]) -> ClientSecret {
        ClientSecret(Secret32::from_bytes(b))
    }

    pub fn expose(&self) -> &[u8; 32] {
        self.0.expose()
    }

    fn entry(&self, until: Option<WallMs>) -> ct::Client {
        ct::Client { secret_hash: osis_base::hash::hash(self.expose()), until }
    }
}

/// One entry of `clients.0^`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Client {
    /// The actor the node acts as for it: grant it what the client may reach.
    pub actor: Tid,
    /// When its sessions end (none: they do not).
    pub until: Option<WallMs>,
}

fn secret_of(v: Value) -> Result<ClientSecret> {
    v.as_array::<32>().map(ClientSecret::from_bytes).ok_or_else(|| crate::port::codec::bad("client secret"))
}

impl Osis {
    /// Registers a thin client: mints its actor, owned by the account,
    /// with secrets of its own, placed in the home group so the account's devices can grant to
    /// it, and writes its `clients.0^` entry, all in one transaction. Returns the actor and the
    /// secret, shown only here. An `until` not in the future is `Invalid`. Grants decide what the
    /// client reaches (it starts with none).
    pub fn add_client(&self, until: Option<WallMs>) -> Result<(Tid, ClientSecret)> {
        if self.is_attached() {
            let v = self.rcall(method::ADD_CLIENT, vec![crate::port::codec::opt(until, |w| Value::uint(w.0))])?;
            let mut a = crate::port::codec::Args::new(v)?;
            return Ok((a.tid()?, secret_of(a.next()?)?));
        }
        if until.is_some_and(|u| u <= self.now()) {
            return Err(Error::Invalid("a client's until must be in the future".into()));
        }
        let secret = ClientSecret::generate();
        let entry = secret.entry(until);
        let (me, node, home) = (self.me(), self.node(), self.home());
        let (actor, done) = self.engine(|e| {
            e.mint_actor(&me, |a| {
                let mut m = osis_node::Mutation::new();
                m.op(node, &ct::CLIENTS, PathOp { path: vec![PathSeg::Key(Value::Tid(a))], op: Op::Set(entry.to_value()) })?;
                m.op(home, &ct::GROUP, crate::write::group_op(true, a, true))?;
                m.act_as(me);
                Ok(m)
            })
        })?;
        self.carry(done)?;
        Ok((actor, secret))
    }

    /// This node's thin clients (`clients.0^`).
    pub fn clients(&self) -> Result<Vec<Client>> {
        if self.is_attached() {
            let v = self.rcall(method::CLIENTS, vec![])?;
            return crate::port::codec::Args::of(vec![v]).list()?.into_iter().map(|c| {
                let mut a = crate::port::codec::Args::new(c)?;
                let actor = a.tid()?;
                let until = a.opt()?.map(|w| w.as_uint().map(WallMs).ok_or_else(|| crate::port::codec::bad("time"))).transpose()?;
                Ok(Client { actor, until })
            }).collect();
        }
        Ok(self.get(self.node(), ct::CLIENTS)?.unwrap_or_default().into_iter().map(|(actor, c)| Client { actor, until: c.until }).collect())
    }

    /// Revokes a thin client: its sessions end at once, its actor is demoted from everything it
    /// holds an edge on (the normal removals with their rotations, spec/permissions.md §3), then
    /// the entry goes. `false` when there is no entry. The entry stays, ended, until every
    /// demotion went, so a failure or a crash halfway is retried by calling this again.
    ///
    /// No pre-sync: a client actor's commits are all this node's own (one node serves a client),
    /// so there is nothing elsewhere to wait for. A demotion this node may not make fails here, as
    /// does a grant on a thing this node reads at another node (`Unsupported`, the sessions ended,
    /// the entry staying: move its group home and call this again).
    pub fn remove_client(&self, actor: Tid) -> Result<bool> {
        if self.is_attached() {
            let v = self.rcall(method::REMOVE_CLIENT, vec![Value::Tid(actor)])?;
            return crate::port::codec::Args::of(vec![v]).bool();
        }
        let node = self.node();
        let Some(e) = self.get(node, ct::CLIENTS)?.unwrap_or_default().remove(&actor) else { return Ok(false) };
        // ended under any clock: one moved back revives no half-removed client
        let ended = Some(WallMs(0));
        if e.until != ended {
            self.write_with(|w| w.at(node, ct::CLIENTS).path(Path::root()).put(&actor, &ct::Client { until: ended, ..e }))?;
        }
        for t in self.engine(|x| x.grants_of(&actor)) {
            self.not_routed("remove_client", t)?;
            let done = self.guarded(&[t], |x| Ok(x.demote(&t, &Demotion { holder: actor, new: None, presync: PreSync::Synced, keep: None })?))?;
            self.carry(done)?;
        }
        self.write_with(|w| w.at(node, ct::CLIENTS).path(Path::root()).remove_key(&actor))?;
        Ok(true)
    }

    /// A new bearer secret for a client: the old hash is gone, with its live connections; the
    /// actor and its grants stay. `Invalid` when there is no entry.
    pub fn rotate_client_secret(&self, actor: Tid) -> Result<ClientSecret> {
        if self.is_attached() {
            return secret_of(self.rcall(method::ROTATE_CLIENT_SECRET, vec![Value::Tid(actor)])?);
        }
        let node = self.node();
        let e = self.get(node, ct::CLIENTS)?.unwrap_or_default().remove(&actor).ok_or_else(|| Error::Invalid(format!("no client {actor}")))?;
        let secret = ClientSecret::generate();
        let entry = secret.entry(e.until);
        self.write_with(|w| w.at(node, ct::CLIENTS).path(Path::root()).put(&actor, &entry))?;
        Ok(secret)
    }
}
