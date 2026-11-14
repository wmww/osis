//! Clients of this node by a secret (notes/client-port.md §3): `clients^.0` on the node thing
//! (spec/data-model.md §9) lists a client actor per client with the hash of its bearer secret
//! and its end. The node mints the actor (an actor whose first admin is the account, like a link's K) and
//! acts as it for the client's session (the client port, spec/wire.md §11.2); what the client may read and write is
//! that actor's grants, nothing else. Any admin of the node thing may edit the registry.

use crate::error::{Error, Result};
use crate::handle::Osis;
use osis_base::{Tid, Value, Time};
use osis_crdt::{Op, PathOp, PathSeg};
use osis_crypto::Secret32;
use osis_engine::flows::Demotion;
use osis_schema::core_types as ct;
use osis_schema::{Codec, p};

/// A client's bearer secret: shown once by `add_client` and `rotate_client_secret`; osis keeps
/// only its hash. Whoever holds it is the client. `Debug` is redacted; zeroized on drop.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientSecret(pub(crate) Secret32);

impl ClientSecret {
    fn generate() -> ClientSecret {
        ClientSecret(Secret32::random(&mut osis_crypto::OsRng))
    }

    /// A secret from its 32 bytes, as `expose` gave them.
    pub fn from_bytes(b: [u8; 32]) -> ClientSecret {
        ClientSecret(Secret32::from_bytes(b))
    }

    /// The secret's bytes, to hand to the client.
    pub fn expose(&self) -> &[u8; 32] {
        self.0.expose()
    }

    fn entry(&self, until: Option<Time>) -> ct::Client {
        ct::Client { secret_hash: osis_base::hash::hash(self.expose()), until }
    }
}

/// A client with an actor of its own (`Osis::add_client`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Client {
    /// The actor the node acts as for it: grant it what the client may reach.
    pub actor: Tid,
    /// When its sessions end (none: they do not).
    pub until: Option<Time>,
}

impl Osis {
    /// Registers a client: a new actor of this account, which the account's nodes can grant to.
    /// Returns the actor and the secret, shown only here. An `until` not in the future is `Invalid`. Grants decide what the
    /// client reaches (it starts with none).
    /// `Unsupported` on a client with its own actor.
    pub fn add_client(&self, until: Option<Time>) -> Result<(Tid, ClientSecret)> {
        let now = self.now()?;
        if until.is_some_and(|u| u <= now) {
            return Err(Error::Invalid("a client's until must be in the future".into()));
        }
        let secret = ClientSecret::generate();
        let entry = secret.entry(until);
        let (me, node) = (self.me(), self.node());
        let home = self.home();
        let (actor, _) = self.engine(|e| {
            e.mint_actor(&me, |a| {
                let mut m = osis_engine::Mutation::new();
                m.op(home, &ct::GROUP, crate::write::group_op(true, a, true))?;
                Ok(m)
            })
        })?;
        // a commit of the node's own: only it writes its thing (a crash before it leaves an
        // actor no client can reach, holding nothing)
        self.engine(|e| {
            let mut m = osis_engine::Mutation::new();
            m.op(node, &ct::CLIENTS, PathOp { path: vec![PathSeg::Key(Value::Tid(actor))], op: Op::Set(entry.to_value()) })?;
            e.commit(m)
        })?;
        Ok((actor, secret))
    }

    /// The clients registered with `add_client`.
    /// `Unsupported` on a client with its own actor.
    pub fn clients(&self) -> Result<Vec<Client>> {
        Ok(self.at(self.node(), ct::CLIENTS).get()?.unwrap_or_default().into_iter().map(|(actor, c)| Client { actor, until: c.until }).collect())
    }

    /// Removes a client: its sessions end at once, its actor loses every role it holds, then
    /// the entry goes. `false` when there is no entry. The entry stays, ended, until every role is
    /// gone, so a failure or a crash halfway is retried by calling this again.
    ///
    /// Unlike `set_role` and `remove_node`, this takes no options and never waits: all a client
    /// wrote went through this node, so there is nothing elsewhere to catch up on, and a client's
    /// actor has no node to keep a copy. A role this node may not remove fails here, as does one
    /// on a thing this node reads at another node (`Unsupported`, the sessions ended, the entry
    /// staying: move its group home and call this again).
    /// `Unsupported` on a client with its own actor.
    pub fn remove_client(&self, actor: Tid) -> Result<bool> {
        let node = self.node();
        let Some(e) = self.at(node, ct::CLIENTS).get()?.unwrap_or_default().remove(&actor) else { return Ok(false) };
        // ended under any clock: one moved back revives no half-removed client
        let ended = Some(Time(0));
        if e.until != ended {
            let mut w = self.write();
            w.at(node, ct::CLIENTS).path(p![actor]).set(&ct::Client { until: ended, ..e })?;
            w.commit()?;
        }
        for t in self.engine(|x| x.grants_of(&actor)) {
            self.engine(|x| x.demote(&t, &Demotion { holder: actor, new: None, retain: None }))?;
        }
        let mut w = self.write();
        w.at(node, ct::CLIENTS).path(p![actor]).remove()?;
        w.commit()?;
        Ok(true)
    }

    /// A new bearer secret for a client: the old one stops working, and its live connections end; the
    /// actor and its grants stay. `Invalid` when there is no entry.
    /// `Unsupported` on a client with its own actor.
    pub fn rotate_client_secret(&self, actor: Tid) -> Result<ClientSecret> {
        let node = self.node();
        let e = self.at(node, ct::CLIENTS).get()?.unwrap_or_default().remove(&actor).ok_or_else(|| Error::Invalid(format!("no client {actor}")))?;
        let secret = ClientSecret::generate();
        let entry = secret.entry(e.until);
        let mut w = self.write();
        w.at(node, ct::CLIENTS).path(p![actor]).set(&entry)?;
        w.commit()?;
        Ok(secret)
    }
}
