//! Sharing, links, cards, nodes, peers and sync (notes/api.md Sharing and roles, Sync
//! configuration and status) over role flows: each sharing call is one role commit made locally
//! (spec/permissions.md §2); calls that wait for another node are `async` (runtime-agnostic
//! futures). Sync is not built yet: what needs another node fails `NotBuilt`.

use crate::error::{Error, Result};
use crate::handle::{Osis, ReadOnly};
use osis_base::{Role, Tid, Time};
use osis_engine::flows;
use osis_schema::core_types as ct;
use std::collections::{BTreeMap, BTreeSet};

/// When a grant ends and what its holder may grant others (`Osis::grant`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GrantOpts {
    /// The grant ends at this time.
    pub until: Option<Time>,
    /// The highest role the holder may grant others, at most its own.
    pub may_grant: Option<Role>,
}

/// What a group contains. Being a member grants nothing: who may read a thing is who holds a role
/// on it (`Osis::grants`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Member {
    /// A thing in the group.
    Item(Tid),
    /// A group whose own members count as members of this one.
    Subgroup(Tid),
}

impl Member {
    /// The member's tid, whichever way it is in the group.
    pub fn tid(self) -> Tid {
        self.parts().0
    }

    /// The thing, and whether it is a subgroup.
    pub(crate) fn parts(self) -> (Tid, bool) {
        match self {
            Member::Item(t) => (t, false),
            Member::Subgroup(t) => (t, true),
        }
    }
}

/// What a holder is, as its creator declared: an actor's creation fixes this, so it reads alike on
/// every node and never changes, and nothing checks it. A holder whose creation has not reached
/// this node reads as `Actor`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HolderKind {
    /// An account, team, group or other actor.
    Actor,
    /// The actor of a share link: those who joined by the link hold through it.
    Link,
    /// A key: a node, or a share link's own key, which holds that link's actor
    /// until the link ends.
    Key,
}

/// Whether this node may end `holder`'s grant on `t` for `Osis::leave`.
fn leave_allowed(e: &mut osis_engine::Engine, holder: Tid, t: Tid, own: bool) -> Result<()> {
    match e.may_remove(&t, &holder)? {
        Some(flows::Untie::Explicit) if !own => Err(Error::Invalid(format!("this node is an admin of {t}: use set_role"))),
        None if !own => Err(Error::Permission { tid: holder, needs: Role::Admin }),
        _ => Ok(()),
    }
}

/// One way an actor holds a role on a thing (`Osis::holders`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Holder {
    /// The actor holding the role.
    pub actor: Tid,
    /// What the actor is.
    pub kind: HolderKind,
    /// The role this way gives: the least along it.
    pub role: Role,
    /// When this way ends: the earliest end along it. One that has ended is not listed.
    pub until: Option<Time>,
    /// The actors between the thing and this holder, nearest the thing first: empty for a grant
    /// on the thing itself, the link's actor for someone who joined by a link, a team for its
    /// members.
    pub through: Vec<Tid>,
}

/// How `Osis::set_role` takes a role away.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SetRoleOpts {
    /// On removal: whether the holder's nodes retain a read-only copy of what it could read (`true`)
    /// or erase it (`false`). `None`: the thing's default (`core::RetentionSetting::retain_copies`), and
    /// erase for a node leaving its account. `Invalid` when a role remains.
    pub retain_copy: Option<bool>,
}

/// How a link made by `Osis::make_link` ends. The link names the node that made it and its relays,
/// so a redeemer reaches that node while it is online: anyone holding the link can dial it, also
/// after the link ends, until `Osis::rotate_peer_address`; dialing opens nothing the link no
/// longer grants.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LinkOpts {
    /// The link expires. It closes when one of your nodes next syncs after `until`: until then
    /// anyone holding the link can still join.
    pub until: Option<Time>,
    /// The first redemption ends the link.
    pub single_use: bool,
}

/// Names a link (`LinkInfo::id`, `Osis::revoke_link`). Its text form is what `FromStr` reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LinkId(pub(crate) Tid);

impl LinkId {
    /// The actor those who joined by this link hold through: `Holder::through` names it, and
    /// `Osis::holders` of it lists them.
    pub fn actor(&self) -> Tid {
        self.0
    }
}

impl std::fmt::Display for LinkId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0.to_uri())
    }
}

impl std::str::FromStr for LinkId {
    type Err = Error;
    fn from_str(s: &str) -> Result<LinkId> {
        s.trim().parse().map(LinkId).map_err(|_| Error::Invalid(format!("no link id: {s}")))
    }
}

/// A link of this account (`links`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LinkInfo {
    /// What `revoke_link` takes.
    pub id: LinkId,
    /// The thing it shares.
    pub target: Tid,
    /// The role it gives.
    pub role: Role,
    /// When it expires.
    pub until: Option<Time>,
    /// The first redemption ends it.
    pub single_use: bool,
}

/// A thing this account was given a role on that no node of it syncs yet (`Osis::invitations`):
/// `accept_invite` syncs it, `leave` turns it down.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Invitation {
    /// The thing.
    pub thing: Tid,
    /// The role given.
    pub role: Role,
    /// The account that gave it.
    pub from: Tid,
    /// This node took the grant's delivery: its keys are here.
    pub taken: bool,
    /// This account acted on it before: accepted it, filed it outside the synced groups, or
    /// stopped syncing it. False for an invitation not acted on yet.
    pub acted: bool,
}

fn bad(what: &str) -> impl Fn(osis_label::Error) -> Error + '_ {
    move |e| Error::Invalid(format!("{what}: {e}"))
}

/// A secret-bearing text form: checked by `$parse` when parsed (`parse` reads it), redacted in `Debug`.
macro_rules! secret_text {
    ($(#[$m:meta])* $n:ident, $inner:ty, $parse:expr) => {
        $(#[$m])*
        #[derive(Clone, PartialEq, Eq)]
        pub struct $n(pub(crate) String);
        impl $n {
            // not every form is parsed back here (a contact card only by contact import)
            #[allow(dead_code)]
            pub(crate) fn parse(&self) -> Result<$inner> {
                ($parse)(self.0.as_str())
            }
        }
        impl std::str::FromStr for $n {
            type Err = Error;
            fn from_str(s: &str) -> Result<$n> {
                let s = s.trim();
                ($parse)(s)?;
                Ok($n(s.to_string()))
            }
        }
        impl std::fmt::Display for $n {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(&self.0)
            }
        }
        impl std::fmt::Debug for $n {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(concat!(stringify!($n), "(..)"))
            }
        }
    };
}

pub(crate) use secret_text;

secret_text!(
    /// A share link (`osis://link/...`): whoever holds this text can redeem it, so hand it over as a
    /// secret.
    ShareLink, osis_label::ShareLink, |s| osis_label::ShareLink::from_text(s).map_err(bad("link"))
);
impl ShareLink {
    /// The thing the link shares.
    pub fn target(&self) -> Result<Tid> {
        Ok(self.parse()?.target)
    }
}
secret_text!(
    /// A contact card: a read link to an account's profile.
    ContactCard, osis_label::ShareLink, |s| osis_label::ShareLink::from_text(s).map_err(bad("contact card"))
);

/// A transport URL, such as `quic://example.org:4040`: where something listens or is dialed.
/// `FromStr` checks it; a `quic://` URL without a port gets `:4040` spelled out.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Url(String);

impl Url {
    /// Its text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::str::FromStr for Url {
    type Err = Error;
    fn from_str(s: &str) -> Result<Url> {
        let s = s.trim();
        let bad = |why: &str| Err(Error::Invalid(format!("URL {s:?}: {why}")));
        if s.split_once("://").is_none_or(|(scheme, rest)| scheme.is_empty() || rest.is_empty()) {
            return bad("needs scheme://");
        }
        // `#` starts an address's key
        if s.contains('#') || s.contains(char::is_whitespace) {
            return bad("no `#` or spaces");
        }
        let url = osis_transport::quic::explicit_port(s);
        if url.len() > osis_base::format::MAX_URL_BYTES {
            return bad("too long");
        }
        Ok(Url(url))
    }
}

impl std::fmt::Display for Url {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// How to reach a node: a transport URL and the node's key (`<url>#<base64url key>`).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Address(pub(crate) osis_label::Address);

impl std::str::FromStr for Address {
    type Err = Error;
    /// A `quic://` URL without a port gets `:4040` spelled out, so one node has one address.
    fn from_str(s: &str) -> Result<Address> {
        let mut a = osis_label::address_from_text(s.trim()).map_err(bad("address"))?;
        a.url = osis_transport::quic::explicit_port(&a.url);
        if a.url.len() > osis_base::format::MAX_URL_BYTES {
            return Err(Error::Invalid(format!("address: URL over {} bytes", osis_base::format::MAX_URL_BYTES)));
        }
        Ok(Address(a))
    }
}

impl std::fmt::Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&osis_label::address_to_text(&self.0))
    }
}

impl Address {
    /// From a transport URL and the node's 32-byte key.
    pub fn new(url: &Url, key: [u8; 32]) -> Address {
        Address(osis_label::Address { url: url.0.clone(), key })
    }

    /// This address as a `peer://` relay item (`<hex key>@<socket address>`), when its URL is
    /// `peer://` and one socket address.
    pub(crate) fn relay_item(&self) -> Option<String> {
        let it = osis_transport::p2p::items(&self.0.url).ok()?;
        let [addr] = it.direct.as_slice() else { return None };
        it.relays.is_empty().then(|| osis_transport::p2p::Relay { key: self.0.key, addr: *addr }.item())
    }

    /// Where to dial.
    pub fn url(&self) -> Url {
        Url(self.0.url.clone())
    }

    /// The node's key, which it proves when dialed.
    pub fn key(&self) -> [u8; 32] {
        self.0.key
    }
}

/// A node of this account and its role on the account (`Osis::nodes`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(missing_docs)]
pub struct AccountNode {
    pub node: Tid,
    pub role: Role,
}

fn edge(role: Role, o: GrantOpts) -> ct::Edge {
    ct::Edge { role, until: o.until, invite: o.may_grant, tied: None }
}

/// Whether an admin's grant of `role` to `h` on `t` would lower `h`'s grant still in the state (a
/// present one, or one past its `until` not yet removed): `h`'s departure, whose rotation only a
/// demotion carries (spec/permissions.md §3), so it takes `set_role`.
fn below_held(e: &osis_engine::Engine, t: &Tid, h: &Tid, role: Role) -> bool {
    e.role_on(t) == Some(Role::Admin) && e.key_role(t, h).is_some_and(|r| role < r)
}

/// `UnknownActor` unless `h` is known here as an actor a grant can box: a thing with a first
/// admin, or a key actor (a node or a link key) whose `keys.0` is held.
fn known_actor(e: &mut osis_engine::Engine, h: Tid) -> Result<()> {
    if !e.knows(&h) || (e.first_admin(&h).is_none() && e.get_typed(&h, &ct::KEYS)?.is_none()) {
        return Err(Error::UnknownActor { tid: h });
    }
    Ok(())
}

/// `ReadOnly::holders`, read by `r` (as its actor: nothing behind an actor it may not read).
pub(crate) fn holders_in(r: &crate::read::Reader<'_>, target: Tid) -> Vec<Holder> {
    let mut out: Vec<Holder> = Vec::new();
    // the ways looked behind so far, per actor: a way none of them beats goes behind it too,
    // else a member's role through a nested actor is that of the actor's first way in
    let mut seen: BTreeMap<Tid, Vec<(Role, Option<Time>)>> = BTreeMap::new();
    let mut queue = std::collections::VecDeque::<(Tid, Option<Role>, Option<Time>, Vec<Tid>)>::from([(target, None, None, Vec::new())]);
    while let Some((at, role, until, through)) = queue.pop_front() {
        for (actor, g) in r.grants(at) {
            if actor == target || through.contains(&actor) {
                continue;
            }
            let way = Holder {
                actor,
                kind: r.holder_kind(actor),
                role: role.map_or(g.role, |x| x.min(g.role)),
                until: [until, g.until].into_iter().flatten().min(),
                through: through.clone(),
            };
            let ways = seen.entry(actor).or_default();
            let beaten = ways.iter().any(|(r, u)| *r >= way.role && (u.is_none() || way.until.is_some_and(|w| Some(w) <= *u)));
            if !beaten {
                ways.push((way.role, way.until));
                let mut on = way.through.clone();
                on.push(actor);
                queue.push_back((actor, Some(way.role), way.until, on));
            }
            out.push(way);
        }
    }
    out
}

fn needs_admin(e: osis_engine::Error) -> Error {
    match e {
        osis_engine::Error::Permission { tid } => Error::Permission { tid, needs: Role::Admin },
        e => e.into(),
    }
}

impl ReadOnly {
    /// Everyone who holds a role on `target`, directly or through an actor that holds one (an account
    /// through a group, a joiner through a link), nearest first. An actor with several ways in is
    /// listed once per way: the shortest to each grant it holds them by, and a longer one when it
    /// gives more, so its best role and latest end are among its entries. Who holds through an actor:
    /// `holders` of that actor, or those here with it in `through`. Grants one level down, with
    /// `may_grant` and whether a grant goes with a membership: `grants`. Nothing behind an actor
    /// this node (on a client with its own actor, that actor) does not read: its roster is not
    /// shown here (`grants`).
    pub fn holders(&self, target: Tid) -> Result<Vec<Holder>> {
        if let Some(at) = self.remote(target, "holders")? {
            return crate::port::codec::holders_from(self.remote_call(&at, crate::port::method::HOLDERS, vec![osis_base::Value::Tid(target)], crate::port::VALUE_REPLY)?);
        }
        Ok(self.read_answer(|| crate::track::thing_key("holders", target), crate::watch::Filter::Due(crate::watch::Watch::Roles), move |r| holders_in(r, target)))
    }

    /// The profile thing of an account whose card this node imported, if any.
    /// `Unsupported` on a client with its own actor.
    pub fn profile_of(&self, account: Tid) -> Result<Option<Tid>> {
        self.local("profile_of")?;
        let key = format!("{PROFILE_OF}{account}");
        // written only by `import_contact`: a tracking handle has nothing to listen to here
        let b = self.engine(|e| e.app_record(&key))?;
        let Some(b) = b else { return Ok(None) };
        let t = String::from_utf8(b).map_err(|_| Error::Storage("profile record".into()))?;
        t.parse().map(Some).map_err(|_| Error::Storage("profile record".into()))
    }

}

impl Osis {
    /// Grants `holder` `role` on `target`: adds a holder, raises a role, or changes `until` and
    /// `may_grant` (what `opts` leaves out goes). It never waits and never lowers a role: a role below
    /// the holder's present one, or below one whose grant ended and is still on record, is `Invalid`
    /// and takes `set_role`.
    ///
    /// `set_role` also adds and raises, and this overlap is on purpose: `grant` is the call that
    /// does not block and takes no role away, for sync code and for callers that mean only that, and
    /// the only one that sets `until` and `may_grant`. What it does take away, it takes as `set_role`
    /// does: a `may_grant` below the present one undoes the grants the
    /// holder made by it that this node had not received, and a role below one the holder had before
    /// (it left, or its grant ended and was removed) undoes what it wrote with that role that this
    /// node had not received.
    ///
    /// A thing's first grant to anyone but its first admin also makes it sync (`sync`), so every
    /// holder of a role on it can read it, whatever groups it is in.
    ///
    /// Needs admin on the target (or a `may_grant` of at least `role`, for someone with no grant yet;
    /// a grant that ended above `role` counts as one until an admin takes it away), else `Permission`,
    /// and the holder's keys here (a contact card, a shared group, pairing), else `UnknownActor`.
    /// Each grant costs about 2.6 KB of keys: to share with many, grant one group. `Unsupported` on
    /// a client with its own actor.
    pub fn grant(&self, target: Tid, holder: Tid, role: Role, opts: GrantOpts) -> Result<()> {
        self.local_at(target, "grant")?;
        if !self.holds(target) {
            return Err(Error::UnknownThing { tid: target });
        }
        self.locked(|l| {
            let e = l.engine();
            known_actor(e, holder)?;
            // a change keeps the tie to a membership; a new hand grant has none
            let cur = e.roster(&target).get(&holder).copied();
            if cur.is_some_and(|x| role < x.role) || below_held(e, &target, &holder, role) {
                return Err(Error::Invalid("a lower role takes set_role".into()));
            }
            let tied = cur.and_then(|x| x.tied).map(flows::tied::tie_ct);
            e.grant(&target, &holder, &ct::Edge { tied, ..edge(role, opts) }).map_err(needs_admin)
        })?;
        Ok(())
    }

    /// Adds `member` to `group` and grants the group `role` on it, tied together: the grant goes
    /// when the membership goes (`GroupWrite::remove`), so the group's holders
    /// reach what is in the group for as long as it is, through the group's sync. Being a member
    /// alone grants nothing, and a plain `grant` to the group stays when the membership goes.
    ///
    /// Already a member, nothing more is written to the group. A grant of the group at `role` or
    /// above stays as it is, tied or not, and a raise of a grant made by hand stays untied.
    ///
    /// Two commits, not one: the membership, the grant. A crash between them
    /// leaves the earlier ones, and calling this again finishes the rest.
    ///
    /// Needs write on the group and admin on the thing (or a `may_grant` of at least `role`, the
    /// group having no grant yet), else `Permission` before anything is written. `Invalid`, as for
    /// `grant`, below a grant of the group ended and still on record. To add without granting: `Write::group`. `Unsupported` on a client with its own actor.
    pub fn add_with_grant(&self, member: Member, group: Tid, role: Role) -> Result<()> {
        self.local_at(group, "add_with_grant")?;
        let (tid, subgroup) = member.parts();
        for x in [tid, group] {
            if !self.holds(x) {
                return Err(Error::UnknownThing { tid: x });
            }
        }
        let existing = self.grants(tid)?.get(&group).copied();
        // a tied grant whose membership is gone here is tied again to the new one
        let retie = existing.is_some_and(|x| x.with_membership) && self.engine(|e| e.tie_dead(&tid, &group))?;
        let role = existing.filter(|_| retie).map_or(role, |x| x.role.max(role));
        let grant = retie || existing.is_none_or(|e| e.role < role);
        if grant && !self.engine(|e| e.may_grant(&tid, &group, role))? {
            return Err(Error::Permission { tid, needs: Role::Admin });
        }
        if grant && existing.is_none() && self.engine(|e| below_held(e, &tid, &group, role)) {
            return Err(Error::Invalid("the group held a higher role: set_role first".into()));
        }
        let listed = self.read_local(|r| {
            let gs = r.groups_of(tid);
            if subgroup { gs.subgroup_of.contains(&group) } else { gs.item_of.contains(&group) }
        });
        if !listed {
            let mut w = self.write();
            w.sharing = true;
            w.group(group).add(member)?;
            w.commit()?;
        }
        if !grant {
            return Ok(());
        }
        // tied to the membership's live element (written above, or already there); a grant made
        // by hand stays untied
        let tied = existing.is_none_or(|x| x.with_membership);
        self.engine(|e| {
            let tie = match tied {
                true => Some(e.placement(&tid, &group, subgroup)?.ok_or_else(|| Error::Invalid(format!("{tid} is not in {group} here")))?),
                false => None,
            };
            let edge = ct::Edge { role, until: None, invite: None, tied: tie.map(flows::tied::tie_ct) };
            e.grant(&tid, &group, &edge).map_err(needs_admin)
        })?;
        Ok(())
    }

    /// Removes the grants of `pairs` (thing, group) tied to a membership gone here, where this
    /// node may as a self-removal (`Write::commit` after a removal). Otherwise, or on failure, a
    /// node that may remove it does so later (node-sync's obligation).
    pub(crate) fn untie_now(&self, pairs: &[(Tid, Tid)]) {
        for (t, g) in pairs {
            self.engine(|e| {
                let due = e.may_remove(t, g).ok().flatten() == Some(flows::Untie::SelfRemoval) && e.tie_dead(t, g).unwrap_or(false);
                if due { e.untie(t, g).ok() } else { None }
            });
        }
    }

    /// Makes `holder`'s role on `target` this one: raises, lowers, or with `None` removes. The usual
    /// way to change a role (`grant` says why both exist). A role that does not change writes
    /// nothing. Someone with no role gets a `grant` with default options, or with `None` nothing is
    /// written. `until` and `may_grant` stay as they are (`may_grant` capped at the new role): `grant`
    /// sets those.
    ///
    /// Lowering or removing a role writes at once, keeping what this node has received of the
    /// holder's work and what any other writer had received before the removal (each vouches for
    /// it in an addendum, spec/permissions.md §5.2). What reached no writer in time (an offline
    /// device, a reader or a host alone) is undone until the holder is granted the role again. To
    /// keep more, sync first: `wait_synced(SyncScope::Thing(target))` under your runtime's timeout,
    /// removing anyway when it times out or fails `Unsynced` (crate docs, Sharing). A raise waits
    /// for nothing.
    ///
    /// A role below one whose grant ended and is still on record ends the old grant in a commit of
    /// its own (a failure between the two leaves the holder with no role, as it had: call again).
    /// `SetRoleOpts::retain_copy` with a role is `Invalid`.
    ///
    /// A removal follows every way the holder has in (`holders`) until none is left: dropped or
    /// failed midway, the ways already removed stay so (call again). A holder who
    /// joined by a link of this account is removed together with the link's key, in one commit:
    /// it may have kept the link's text. The link then stops working for anyone who has not used
    /// it yet (make a new one), and its other joiners stay. A joiner's role cannot be changed, only
    /// removed (`Invalid`; `grant` gives it a role of its own). Nor can this call reach through
    /// another actor (a team, a link of another account): `Invalid`, naming the actor to set
    /// the role on.
    ///
    /// A writer that changed the keys so only it can read locks the others out; removing it (or
    /// lowering it below write) here recovers: the new keys replace the ones it made. Lacking keys
    /// made by a writer it keeps, the lowering applies without changing the keys, and nothing is
    /// written under the thing here until that writer changes them (or is removed too).
    ///
    /// `Unsupported` on a client with its own actor, and on a thing this node reads at another node: move its group
    /// home first. A removal written to the copy here would never leave it.
    pub fn set_role(&self, target: Tid, holder: Tid, role: Option<Role>, o: SetRoleOpts) -> Result<()> {
        self.local_at(target, "set_role")?;
        retain_only_on_removal(role, o)?;
        self.change_role(target, holder, role, o)
    }

    /// `set_role`'s writes.
    fn change_role(&self, target: Tid, holder: Tid, role: Option<Role>, o: SetRoleOpts) -> Result<()> {
        // each round removes one way in; the bound only guards against grants that never settle
        for _ in 0..16 {
            let Some(way) = self.holders(target)?.into_iter().find(|h| h.actor == holder) else {
                let Some(r) = role else { return Ok(()) };
                // a grant ended above `r`, still on record: its removal first
                if self.engine(|e| below_held(e, &target, &holder, r)) {
                    self.lower(target, holder, None, o)?;
                }
                return self.grant(target, holder, r, GrantOpts::default());
            };
            match way.through.as_slice() {
                [] => {
                    let cur = self.grants(target)?.get(&holder).copied().ok_or(Error::Invalid(format!("{holder} is no holder of {target}")))?;
                    match role {
                        Some(r) if r == cur.role => return Ok(()),
                        Some(r) if r > cur.role => return self.grant(target, holder, r, GrantOpts { until: cur.until, may_grant: cur.may_grant }),
                        _ => self.lower(target, holder, role, o)?,
                    }
                }
                [k] if self.held_links()?.iter().any(|h| h.k == *k && h.target == target) => {
                    if role.is_some() {
                        return Err(Error::Invalid(format!("{holder} joined {target} by a link: it can only be removed")));
                    }
                    self.remove_joiner(*k, holder, o)?;
                }
                [k, ..] => return Err(Error::Invalid(format!("{holder} reaches {target} through {k}: set its role there"))),
            }
            if role.is_some() {
                return Ok(());
            }
        }
        Err(Error::Invalid(format!("{holder} still reaches {target}")))
    }

    /// The edge `m` holds on `t` after lowering it to `role` (`None`: removed): `until` kept,
    /// `may_grant` capped, the tie kept.
    fn lowered_edge(&self, t: Tid, m: Tid, role: Option<Role>) -> Result<Option<ct::Edge>> {
        let Some(role) = role else { return Ok(None) };
        let cur = self.grants(t)?.get(&m).copied().ok_or(Error::Invalid(format!("{m} is no holder of {t}")))?;
        Ok(Some(ct::Edge { role, until: cur.until, invite: cur.may_grant.map(|i| i.min(role)), tied: self.engine(|e| e.roster(&t).get(&m).and_then(|x| x.tied)).map(flows::tied::tie_ct) }))
    }

    /// Lowers or removes the grant of `m` on `t`: the demotion with this node's frontier and the
    /// target's rotation, in one commit (spec/permissions.md §2, §3, §5).
    fn lower(&self, t: Tid, m: Tid, role: Option<Role>, o: SetRoleOpts) -> Result<()> {
        let new = self.lowered_edge(t, m, role)?;
        // an account's default does not reach its nodes (spec/permissions.md §2)
        let retain = o.retain_copy.or((t == self.inner.home).then_some(false));
        let fd = flows::Demotion { holder: m, new, retain };
        self.engine(|e| e.demote(&t, &fd).map_err(needs_admin))?;
        Ok(())
    }

    /// Ends `holder`'s ways in that exist for `target`: its own grant on it, and its join of any link
    /// to it. `holder` is `me()`, or a group or other actor this node is an admin of (as when a group's
    /// admin drops a thing that was shared into it). The keys change when the target's next writer or
    /// admin writes, or at once when this node is an admin of `target` by another way. No way in at all
    /// writes nothing.
    ///
    /// A team or other actor the holder reaches `target` through stays: `Invalid` when that is all it
    /// has, naming the actor, as leaving it is what ends the role. `Invalid` for another
    /// actor when this node is an admin of `target`: taking that role away is `set_role`'s.
    /// `Permission` when this node is no admin of `holder`; on a client with its own
    /// actor, for any `holder` but that actor.
    pub fn leave(&self, holder: Tid, target: Tid) -> Result<()> {
        self.local_at(target, "leave")?;
        let own = holder == self.me();
        // the flow below runs with the node's authority: a client ends only its own actor's role
        if self.acting.is_some() && !own {
            return Err(Error::Permission { tid: holder, needs: Role::Admin });
        }
        let holders = self.holders(target)?;
        let links: BTreeSet<Tid> = holders.iter().filter(|h| h.kind == HolderKind::Link && h.through.is_empty()).map(|h| h.actor).collect();
        let ways: Vec<&Holder> = holders.iter().filter(|h| h.actor == holder).collect();
        let mut on: BTreeSet<Tid> = ways.iter().filter_map(|h| match h.through.as_slice() {
            [k] if links.contains(k) => Some(*k),
            _ => None,
        }).collect();
        if self.grants(target)?.contains_key(&holder) {
            on.insert(target);
        }
        if on.is_empty() {
            return match ways.first() {
                Some(h) => Err(Error::Invalid(format!("{holder} holds {target} through {}: leave that", h.through.last().copied().unwrap_or(target)))),
                None => Ok(()),
            };
        }
        // every refusal before anything is written
        for t in &on {
            self.engine(|e| leave_allowed(e, holder, *t, own))?;
        }
        // the target's own grant first: its next rotation still seals a link's K at the keyset
        // it holds, which the leave of K then leaves uncovered (until a joiner rotates K)
        let order: Vec<Tid> = on.iter().copied().filter(|t| *t == target).chain(on.iter().copied().filter(|t| *t != target)).collect();
        for t in order {
            self.leave_grant(holder, t, own)?;
        }
        Ok(())
    }

    /// `leave`'s removal of `holder`'s grant on `t`.
    fn leave_grant(&self, holder: Tid, t: Tid, own: bool) -> Result<()> {
        self.engine(|e| {
            leave_allowed(e, holder, t, own)?;
            // this account's own grant, whichever way this node also holds the target
            e.demote(&t, &flows::Demotion { holder, new: None, retain: None }).map_err(Error::from)
        })?;
        Ok(())
    }

    /// The actors this node retains a read-only copy of after being removed from them (for a client
    /// with its own actor, those it reads). A copy reads as before, and nothing syncs or writes it.
    /// `drop_retained_copy` erases one.
    pub fn retained_copies(&self) -> Result<Vec<Tid>> {
        self.local("retained_copies")?;
        Ok(self.engine(|e| {
            let mut v = e.kept_copies();
            // acting as an actor: the copies it reads
            if let Some(a) = self.acting {
                v.retain(|x| e.copy_readable_by(&a, x));
            }
            v
        }))
    }

    /// Erases the retained copy of `actor`, and what only it retained: its disk space is this user's.
    pub fn drop_retained_copy(&self, actor: Tid) -> Result<()> {
        self.local("drop_retained_copy")?;
        self.engine(|e| e.forget_lost(osis_engine::rotation::LostScope::Kept(&[actor])))?;
        Ok(())
    }

    /// Makes a share link to `target` with `role` (read or above: `Invalid` below). Anyone
    /// holding the link can redeem it until `until` or `revoke_link`.
    pub fn make_link(&self, target: Tid, role: Role, opts: LinkOpts) -> Result<ShareLink> {
        self.local_at(target, "make_link")?;
        let me = self.me();
        let peer = self.own_peer();
        let spec = flows::LinkSpec { target, role, until: opts.until.map(|t| osis_base::WallMs(t.0)), hosts: Vec::new(), peers: vec![peer], single_use: opts.single_use };
        let (link, _, _) = self.engine(|e| e.create_link(&me, &spec)).map_err(needs_admin)?;
        Ok(ShareLink(link.to_text().map_err(bad("link"))?))
    }

    /// This node's first-contact reach (spec/wire.md §10): its dialable key and relays.
    fn own_peer(&self) -> osis_label::Peer {
        let key = self.locked(|l| l.secret.public_key());
        osis_label::Peer { dialable: key, relays: self.inner.relays.clone() }
    }

    /// Redeems a link: reaches what it names and joins it, returning the thing. Returns once
    /// this account holds a role on the thing here; it waits for the link's node meanwhile
    /// (wrap it in a timeout). A link this account already reaches the thing by joins nothing.
    /// What the link holds is kept until the join is held elsewhere, a dropped call included.
    pub async fn redeem(&self, link: &ShareLink) -> Result<Tid> {
        self.local("redeem")?;
        let link = link.parse()?;
        let target = link.target;
        if self.engine(|e| e.role_on(&target).is_some()) {
            return Ok(target);
        }
        let mut started = false;
        self.waiting(move |db| {
            if db.engine(|e| e.role_on(&target).is_some()) {
                return Some(Ok(target));
            }
            if !started {
                started = true;
                if let osis_sync::types::Waiting::Never(why) = db.locked(|l| {
                    let w = l.node.redeem(&link);
                    l.handle(osis_sync::Input::Wrote);
                    w
                }) {
                    return Some(Err(Error::Invalid(format!("link: {why}"))));
                }
            }
            None
        })
        .await
    }

    /// The account's links that still work, whichever node made them (one that has not yet synced here
    /// from the node that made it is not listed); filter by `LinkInfo::target`. `Unsupported` on
    /// a client with its own actor, which is also why a node connected with a client secret adds none.
    pub fn links(&self) -> Result<Vec<LinkInfo>> {
        self.local("links")?;
        self.live_links()
    }

    fn live_links(&self) -> Result<Vec<LinkInfo>> {
        Ok(self
            .held_links()?
            .into_iter()
            .filter_map(|h| {
                let e = self.engine(|e| e.roster(&h.k).get(&h.l).copied())?;
                Some(LinkInfo { id: LinkId(h.k), target: h.target, role: e.role, until: e.until, single_use: h.single_use })
            })
            .collect())
    }

    /// The links whose seed thing is the account's and whose K's first admin it is (a co-reader can place a
    /// seed thing in a shared group: it names no link of ours).
    fn held_links(&self) -> Result<Vec<flows::HeldLink>> {
        let me = self.me();
        self.engine(|e| person_links(e, me))
    }

    /// Link actor `k`'s key L (`held_links`).
    fn link_key(&self, k: Tid) -> Result<Tid> {
        self.held_links()?.iter().find(|h| h.k == k).map(|h| h.l).ok_or(Error::Invalid(format!("no link {k} of this account")))
    }

    /// Ends a link: nobody can use it from now on. Those who joined by it keep their role; to remove
    /// one, `set_role`. Writes at once: a join this node has not received yet is undone (one another
    /// writer received stands, as `set_role` says). `Unsupported` on a client with its own actor.
    pub fn revoke_link(&self, id: LinkId) -> Result<()> {
        self.local("revoke_link")?;
        let l = self.link_key(id.0)?;
        self.lower(id.0, l, None, SetRoleOpts::default())
    }

    /// Removes `joiner` from link actor `k` and ends the link in the same commit, under one rotation
    /// (spec/permissions.md §7: a joiner may keep the seed); the other joiners stay holders of K and
    /// need a new link to invite anyone.
    fn remove_joiner(&self, k: Tid, joiner: Tid, o: SetRoleOpts) -> Result<()> {
        let l = self.link_key(k)?;
        self.engine(|e| e.revoke_joiner(&k, &l, &joiner, o.retain_copy).map_err(needs_admin))?;
        Ok(())
    }

    /// This account's contact card: a read link to its profile, a thing that also carries what
    /// others need to grant this account a role. Made once per node; later calls return the
    /// same card.
    pub fn contact_card(&self) -> Result<ContactCard> {
        self.local("contact_card")?;
        if let Some(b) = self.engine(|e| e.app_record(CONTACT))? {
            return Ok(ContactCard(String::from_utf8(b).map_err(|_| Error::Storage("contact record".into()))?));
        }
        let p = self.profile()?;
        let link = self.make_link(p, Role::Read, LinkOpts::default())?;
        let card = ContactCard(link.0);
        self.engine(|e| e.set_app_record(CONTACT, card.0.as_bytes()))?;
        Ok(card)
    }

    /// This account's profile thing, made with the account: the target of its contact card. The
    /// account writes its profile aspects on it (`name.0`, `contact:*`); everyone holding the
    /// card reads them. Every node of the account knows it (a new node from its pairing
    /// offer), though a node paired a moment ago may not hold the thing yet.
    pub fn profile(&self) -> Result<Tid> {
        self.local("profile")?;
        let b = self.engine(|e| e.app_record(crate::handle::PROFILE))?.ok_or_else(|| Error::Storage("no profile record".into()))?;
        Ok(Tid::from_bytes(b.as_slice().try_into().map_err(|_| Error::Storage("profile record".into()))?))
    }

    /// Imports a contact card: accepts the profile it names (spec/sync-set.md §4) and returns
    /// the account once its keys are here, usable in `grant`. Waits for the card's node
    /// meanwhile (wrap it in a timeout).
    pub async fn import_contact(&self, card: &ContactCard) -> Result<Tid> {
        self.local("import_contact")?;
        let link = card.parse()?;
        let p = link.target;
        let mut started = false;
        let who = self
            .waiting(move |db| {
                let found = db.engine(|e| e.first_admin(&p).filter(|a| e.account_holder_keys(a).is_ok()));
                if let Some(a) = found {
                    return Some(Ok(a));
                }
                if !started {
                    started = true;
                    if let osis_sync::types::Waiting::Never(why) = db.locked(|l| {
                        let w = l.node.redeem(&link);
                        l.handle(osis_sync::Input::Wrote);
                        w
                    }) {
                        return Some(Err(Error::Invalid(format!("contact card: {why}"))));
                    }
                }
                None
            })
            .await?;
        self.engine(|e| e.set_app_record(&format!("{PROFILE_OF}{who}"), p.to_string().as_bytes()))?;
        Ok(who)
    }

    /// The things this account was given a role on that no node of it syncs yet (spec/sync-set.md
    /// §4), newest grant last.
    pub fn invitations(&self) -> Result<Vec<Invitation>> {
        self.local("invitations")?;
        let v = self.engine(|e| e.invitations())?;
        Ok(v.iter().map(|i| Invitation { thing: i.thing, role: i.role, from: i.from, taken: i.taken, acted: i.acted }).collect())
    }

    /// Accepts an invitation: `thing` becomes a subgroup of `into`, a group this node syncs or
    /// one under it (`Invalid` otherwise), so every node of the account syncs it. The same write
    /// as `w.group(into).add(Member::Subgroup(thing))`.
    pub fn accept_invite(&self, thing: Tid, into: Tid) -> Result<()> {
        self.local("accept_invite")?;
        let synced = self.engine(|e| -> Result<bool> {
            let set = e.sync_set()?;
            Ok(set.ids.values().any(|(t, _)| *t == into))
        })?;
        if !synced {
            return Err(Error::Invalid(format!("{into} is not synced here: accept into a synced group")));
        }
        let mut w = self.write();
        w.group(into).add(Member::Subgroup(thing))?;
        w.commit()?;
        Ok(())
    }

    /// This account's nodes: those holding read or above on it (a holder of sync alone keeps
    /// the account's inbox and is no node).
    /// `Unsupported` on a client with its own actor.
    pub fn nodes(&self) -> Result<Vec<AccountNode>> {
        self.local("nodes")?;
        let home = self.home();
        let node_ak = ct::NODE.name();
        self.engine(|e| -> Result<Vec<AccountNode>> {
            let mut out = Vec::new();
            for (m, edge) in e.roster(&home) {
                if edge.role >= Role::Read && (m == e.tid() || e.get(&m, &node_ak)?.is_some()) {
                    out.push(AccountNode { node: m, role: edge.role });
                }
            }
            Ok(out)
        })
    }

    /// Removes a node from this account. This is `set_role(home(), node, None, o)`, here because of
    /// what it returns, which is easy to forget: this account's links still working. The node keeps
    /// their keys, so whoever holds it can read and join through each until `revoke_link`, and
    /// ending them is the caller's choice. None when `node` was not one of this account's.
    /// `Unsupported` on a client with its own actor.
    pub fn remove_node(&self, node: Tid, o: SetRoleOpts) -> Result<Vec<LinkInfo>> {
        self.local("remove_node")?;
        let home = self.home();
        let was = self.grants(home)?.contains_key(&node);
        self.set_role(home, node, None, o)?;
        if was { self.links() } else { Ok(Vec::new()) }
    }

    /// Writes what this node syncs of `groups` (each thing's sync IDs, with what it holds there)
    /// as a bundle to `out`, for another node's `import_bundle`: sync by hand, carried any way.
    pub fn export_bundle(&self, groups: &[Tid], mut out: impl std::io::Write) -> Result<()> {
        self.local("export_bundle")?;
        let bytes = self.locked(|l| -> Result<Vec<u8>> {
            let mut ids = Vec::new();
            for g in groups {
                ids.extend(l.engine().sync_ids(g)?.iter().map(|o| o.id));
            }
            let mut b = Vec::new();
            l.node.export_bundle(&ids, &mut b).map_err(crate::handle::sync_err)?;
            Ok(b)
        })?;
        out.write_all(&bytes).map_err(|e| Error::Storage(e.to_string()))
    }

    /// Reads a bundle: what this node can open applies like synced content.
    pub fn import_bundle(&self, mut input: impl std::io::Read) -> Result<()> {
        self.local("import_bundle")?;
        let mut b = Vec::new();
        input.read_to_end(&mut b).map_err(|e| Error::Storage(e.to_string()))?;
        self.locked(|l| {
            l.node.import_bundle(&mut b.as_slice()).map_err(crate::handle::sync_err)?;
            l.handle(osis_sync::Input::Wrote);
            Ok(())
        })
    }
}

/// `SetRoleOpts::retain_copy` is a removal's word.
fn retain_only_on_removal(role: Option<Role>, o: SetRoleOpts) -> Result<()> {
    if role.is_some() && o.retain_copy.is_some() {
        return Err(Error::Invalid("retain_copy is for removing a role: there is no copy to retain while a role remains".into()));
    }
    Ok(())
}

/// `Osis::held_links`, on this engine.
fn person_links(e: &mut osis_engine::Engine, me: Tid) -> Result<Vec<flows::HeldLink>> {
    let held = e.held_links()?.to_vec();
    Ok(held.into_iter().filter(|h| h.first_admin == me && e.first_admin(&h.k) == Some(me)).collect())
}

/// App record prefix: `profile/<account tid>` -> profile tid text, written by `import_contact`.
const PROFILE_OF: &str = "profile/";

/// App record: this node's contact card text.
const CONTACT: &str = "contact";
