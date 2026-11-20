//! Stated paths and signers as members (notes/write-path-design.md §1-§2, §5,
//! notes/account-membership-design.md §2, §4; not built, not in spec): an oracle of those notes,
//! greenfield, sharing nothing with `joint` (whose authority is a maximum over every path).
//! Findings: notes/path-model-findings.md. README.md, Paths: what is assumed where the notes are
//! open, sizes, how to run.
//!
//! The rule under test.
//! - **Things and edges.** Signers and independent things share one namespace; an edge is
//!   (holder, target) with a role and an optional `until`; record edges stand at the start.
//!   Dependent things are not modelled (a descent of one step is the direct edge).
//! - **Commits.** One signer, a `ts`, the thing written (`on`) and a stated path [A1..Ak]: the
//!   commit uses the edges joining [signer, A1, .., Ak, on] and no other. Kinds: content, an
//!   edge write (setting a holder's edge on `on`; a lowering carries a frontier, a leaf of commit
//!   IDs per thing; it may name the remaining admin it relies on, or carry the mark that lets
//!   its thing go adminless), an addendum (plain content naming a removal and commits it
//!   vouches for), a vouch (the same for role writes: `Vouch`). A commit of several edge writes
//!   on one target (`World::commit`) is one part per write, consecutive in key order, the part on
//!   an edge of its own stated path last.
//! - **Edges in time.** An edge gives its role at `ts` while its `until` is later; a write
//!   giving no role at its own `ts` (none, or an `until` passed) is a removal. A write giving admin
//!   with a later `until` on a standing admin edge (an **end**) is a grant: the last-admin rule
//!   alone reads it (`Rules::until`; as a lowering it fails a required gate either way).
//! - **Hops.** Consecutive members of [signer, A1..Ak, end] are joined by descent (the record
//!   edges down the mint chain) where the first is a mint ancestor of the second and the path does
//!   not mark the pair direct (`World::push_marked`), else by their direct edge. The end is the thing written, except for an edge write whose path ends at the
//!   holder of the edge it sets: a **self-removal**, needing admin on the holder (a signer
//!   leaving by itself states no hop).
//! - **Walk** (§5.1 along one path). Edge-class commits (edge writes, vouches) in key order
//!   (`ts`, signer, ID), skipping the drop set D. One applies iff every edge of its path gives
//!   admin at its `ts`; a self-removal only lowers. An applied explicit write taking an edge h
//!   from admin, **as restored** (the highest role since the last explicit write on h, values an
//!   `until` or a self-removal took included), to below puts in question every earlier held
//!   edge-class commit whose path holds h, not dropped and not void (`Rules::audit_held`, as the
//!   seeds); those its list does not name (`listed`) join D, each with its commit's other
//!   edge-class parts on its thing (`Drops::Commit`), and the walk restarts from the earliest. A
//!   self-removal audits nothing. D only grows until a pass adds nothing.
//! - **Each lowering judged once, at its key** (`Rules::self_void`; finding 16): nothing is
//!   exempt from a lowering's drops and no entry of its list is read as absent. A lowering (an
//!   explicit edge write giving below admin at its `ts`) is judged the first time a pass reaches
//!   it holding its right (its path giving admin, the last-admin rule passed) and taking its edge
//!   from admin: where its own drops would take its authority (`keeps`: its path's edges read back
//!   along the writes that set them, passing over its own drops) it is **void**; else it applies.
//!   A commit of several edge writes takes effect part by part, each judged with the earlier
//!   ones in effect, a lowering's `keeps` passing over its commit's earlier drops too; no part's
//!   drops or seeds reach its own commit; the pass ends once the commit took effect
//!   (`Rules::commit_drops`).
//!   The verdict stands for the rest of the walk: a restart neither re-judges nor re-audits it,
//!   and an applied lowering applies in every later pass unless a later lowering drops it. One
//!   without its right, or taking nothing, has no verdict and is judged by a later pass. D only
//!   grows: nothing is undropped.
//! - **Last admin** (`Rules::last_admin`): an unmarked write taking a **standing** admin edge
//!   (admin, no `until`) of T to anything else applies only where the remaining admin it relies
//!   on is, as the pass stands at it (its commit's earlier parts in effect), a standing admin edge of T other than the one
//!   it lowers: the last edge of its own path where that is one (`Rules::last_hop`: its final hop
//!   joining its last member to T in one edge), else the edge of the holder it names. A judged
//!   lowering is void where that edge stands no more past its drops (`Rules::remains_kept`).
//! - **Content.** A commit on T with path P is valid iff every edge of P gave write just before
//!   its position (the start of its `ts`) and no applied lowering of an edge of P below write is
//!   ordered after it; else iff such a lowering's list names it, a valid addendum by a writer
//!   of T against such a lowering ordered between them lists it (least fixpoint), or P is
//!   re-granted (every edge gives write in the final state, every `until` counted removed) and
//!   the commit is ordered after the first point P gave write (`Regrant`).
//! - **Trust sets.** A trusted lowering R of edge h seeds D with the held edge-class commits
//!   ordered before R whose path holds h, R's list does not name and whose need at h R's value
//!   does not meet (`Rules::seeds_by_need`); a trusted write the
//!   settled walk does not apply is void and loses its seeds, all void ones at once, and the
//!   walk is redone.
//! - **Disputes** (`disputes`): a held explicit lowering of another holder's edge (no
//!   self-removal or invite grant: `Candidates`), not trusted, whose trust changes the reading.
//! - **Leaves.** A node sees a frontier's leaf for a thing only where its view says so
//!   (`View::leaves`); an entry in a leaf it does not see is not listed for it.
//! - **Invites and finalizes.** An edge write without admin on its path applies as an invite
//!   grant where it adds a grant below admin to a holder with none current, within the path's
//!   invite; a finalize ends a grant past its `until`. Neither is explicit: neither audits. A
//!   lowering is judged where it takes its edge down in role or invite (`Rules::any_fall`), and
//!   drops the writes whose need there the edge no longer meets (`need`).
//! - **Purge authors.** A commit states its purge author (an index into [signer, path..]); a
//!   purge request by author P, valid as content along its path, holds the right over the earlier
//!   deltas on its thing naming exactly P where P is on its chain (`purges`).
//! - **Covers.** A compaction snapshot carries content commits; a list naming it names them; a
//!   valid cover's copy of a write shows it whatever the write's own validity (spec/permissions.md
//!   §5.2 Copies, §5.3), so a cover made by a writer not yet holding a removal carries the removed
//!   party's late write for good: the accepted window. `Rules::cover_facts` is the alternative.
//! - **Evidence** (`evidence`): the least set holding a unit's commits, every edge write on an
//!   edge of a held commit's path or on the edge a held lowering names as the admin it relies
//!   on, and the vouches against held removals.
//!
//! `Sim` plays the stolen-node story over that rule (parties, ticks, honest writing and the
//! properties: `Sim::build`, `check`); `rotations` is a small keys layer for A's epochs under a
//! standing dispute.

use crate::{Rng, Role};
use std::collections::{BTreeMap, BTreeSet};

pub type Thing = u8;
pub type Id = usize;
pub type Edge = (Thing, Thing);
pub type Set = BTreeSet<Id>;
pub type Key = (u32, Thing, Id);
pub type Things = BTreeSet<Thing>;
/// An edge's value: its role and its `until`.
pub type Val = (Role, Option<u32>);

#[derive(Clone, Debug, PartialEq)]
pub enum Kind {
    Content,
    Edge {
        holder: Thing,
        role: Role,
        until: Option<u32>,
        frontier: BTreeMap<Thing, Set>,
        /// The holder of the remaining admin edge this write relies on (notes/write-path-design.md
        /// §5, The last admin); read only where its own path's last edge is not one.
        relies: Option<Thing>,
        /// The mark that lets the thing go adminless.
        adminless: bool,
        /// The invite it carries (spec/permissions.md §2), at most its role; an admin edge gives
        /// every invite whatever this says.
        invite: Role,
        /// A finalize: a removal carrying no frontier, ending a grant past its `until`
        /// (spec/permissions.md §2).
        finalize: bool,
    },
    Addendum { removal: Id, list: Set },
    Vouch { removal: Id, list: Set },
    /// A purge request (spec/commits.md §5 Purge; notes/a1-spec/permissions.md §6): it names
    /// deltas on its thing (`Names`) and drops each it holds a right over (`purges`). Content-class,
    /// judged as a content write along its path.
    Purge { names: Names },
    /// A compaction snapshot of its thing (spec/commits.md §5 Covered), carrying the content
    /// commits on it that showed at its writer. Content-class, judged as a content write along its
    /// path. A list or addendum naming it names what it carries (an own cover).
    Cover { carries: Set },
}

/// What a purge request names on its thing (spec/wire.md §4 field 8, `PurgeItem`).
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Names {
    /// `[tid, ak, author]`: the deltas stamped before it whose purge author is exactly this thing.
    Author(Thing),
    /// `[tid, ak]`: every delta stamped before it.
    Aspect,
    /// `[tid, ak, ts, source]`: one delta, stamped before it.
    Commit(Id),
    /// `[tid, created.0]`: the thing's creation (spec/commits.md §5 Destruction): every delta on it,
    /// whatever its `ts`, by the `admin` right alone.
    Destroy,
}

/// Who may purge a delta (spec/commits.md §5 Who and how long), fixed when it is written.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Retention {
    Admin,
    AuthorOrAdmin,
    Writer,
}

impl Kind {
    /// A purge request by author.
    pub fn purge(author: Thing) -> Kind {
        Kind::Purge { names: Names::Author(author) }
    }
    /// An edge write setting `holder`'s edge to `role`, standing, listing nothing.
    pub fn set(holder: Thing, role: Role) -> Kind {
        Kind::Edge { holder, role, until: None, frontier: BTreeMap::new(), relies: None, adminless: false, invite: Role::None, finalize: false }
    }
    /// A finalize of `holder`'s ended grant.
    pub fn finalize(holder: Thing) -> Kind {
        let mut k = Kind::set(holder, Role::None);
        if let Kind::Edge { finalize, .. } = &mut k {
            *finalize = true;
        }
        k
    }
    pub fn inviting(mut self, r: Role) -> Kind {
        if let Kind::Edge { invite, .. } = &mut self {
            *invite = r;
        }
        self
    }
    fn with(mut self, f: impl FnOnce(&mut Option<u32>, &mut BTreeMap<Thing, Set>, &mut Option<Thing>, &mut bool)) -> Kind {
        if let Kind::Edge { until, frontier, relies, adminless, .. } = &mut self {
            f(until, frontier, relies, adminless);
        }
        self
    }
    pub fn until(self, t: u32) -> Kind {
        self.with(|u, _, _, _| *u = Some(t))
    }
    pub fn listing(self, f: BTreeMap<Thing, Set>) -> Kind {
        self.with(|_, l, _, _| *l = f)
    }
    pub fn relying(self, n: Thing) -> Kind {
        self.with(|_, _, r, _| *r = Some(n))
    }
}

#[derive(Clone, Debug)]
pub struct Commit {
    pub signer: Thing,
    pub ts: u32,
    pub path: Vec<Thing>,
    pub on: Thing,
    pub kind: Kind,
    /// The edges the stated path uses (`World::hops`).
    hops: Vec<Edge>,
    /// The path names no thing twice.
    well: bool,
    /// An edge write whose path ends at its holder: a self-removal.
    leave: bool,
    /// The purge author: an index into [signer, path..] (notes/write-path-design.md §1).
    pa: usize,
    /// Who may purge its delta (content only; `Rules::purge_classes` reads it).
    pub ret: Retention,
    /// A compaction snapshot marked as its writer's own cover (`Rules::own_cover` reads it).
    pub own: bool,
    /// The commit this part belongs to: the ID of its first part (its own for a commit of one
    /// part). A commit's parts are consecutive in key order (`World::commit`).
    cid: Id,
    /// A part of a commit of several parts one of which sets an edge of the commit's stated path
    /// (`World::group`; read only by the control `Rules::refuse_shapes`).
    own_path: bool,
    /// The member pairs its path marks as joined by their direct edge (`World::push_marked`).
    pub direct: Vec<usize>,
}

/// How role writes a removal does not list are vouched for (issues/actors-one-mechanism.md,
/// "Role writes of a removed node must be kept on the same terms as its content").
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Vouch {
    /// Nothing vouches for a role write.
    Off,
    /// The simplest reading: a vouch counts when its path gives admin on its thing at its key
    /// in the walk it changes.
    SameWalk,
    /// A vouch counts when its path gives admin on its thing at its key in the walk with no
    /// vouch counting.
    BaseWalk,
}

/// Where a re-granted path's writes count from.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Regrant {
    /// spec/permissions.md §5.2: the first point the settled walk gave the role.
    FirstApplied,
    /// notes/account-membership-design.md §1 (the collateral grantee): the first chained grant
    /// of each edge (spec/permissions.md §4 Chained writes), dropped or not.
    FirstChained,
}

/// What a lowering of an admin edge must leave (notes/write-path-design.md §5, The last admin).
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum LastAdmin {
    Off,
    /// Control (the first round's reading): a lowering from admin that would leave its target no
    /// admin edge alive, of all the walk holds, does not apply unless marked.
    AnyEdge,
    /// The rule: the remaining admin it relies on (its path's last edge, else the one it names)
    /// is a standing admin edge (admin, no `until`) other than the lowered one.
    Named,
    /// Control: as `Named`, a timed admin edge alive at the write counting as standing.
    NamedTimed,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Rules {
    pub vouch: Vouch,
    pub regrant: Regrant,
    /// Control (notes/write-path-design.md §1, Rejected): a lowering never puts in question the
    /// grants its own path rests on, read from the held writes, closed (`chain`).
    pub exempt_chain: bool,
    pub last_admin: LastAdmin,
    /// An addendum vouches for no commit of its own signer (spec/permissions.md §5.2 Addenda
    /// asks only that its writer holds write on the thing, by any path).
    pub no_own_addendum: bool,
    /// A vouch counts for no commit of its own signer.
    pub no_own_vouch: bool,
    /// A node sees a frontier's leaf for every thing an edge write it holds as evidence is on,
    /// besides the things it syncs (finding 5).
    pub evidence_leaves: bool,
    /// Honest writing in `Sim` (a policy, not a judging rule): the state-based rule, writing
    /// whenever the node's own walk shows an owed commit it could write named by nothing of its
    /// own that counts; false, a node answers only the first time its walk applies a removal.
    pub rewrite: bool,
    /// A self-removal of edge h is put in question by a lowering of h like a write through h
    /// (finding 14): else the removed node's backdated leave, which no audit reaches, voids its
    /// own role writes ordered after it.
    pub leave_in_question: bool,
    /// A lowering whose own drops would take its authority is void: it does not apply and drops
    /// nothing (notes/write-path-design.md §1). False (control `-no-void`): it applies and drops.
    pub self_void: bool,
    /// Reading of the audit: a lowering puts in
    /// question the held writes before it resting on its edge, as a trusted write's seeds do, in
    /// place of the applied ones.
    pub audit_held: bool,
    /// Honest writing in `Sim` (a policy, not a judging rule): a remover and a voucher name what
    /// they had received in the order received, leaving out a role write with which their own
    /// walk no longer applies the removal.
    pub stands: bool,
    /// Control of `stands`: the writer keeps the role writes in key order, not in the order it
    /// received them.
    pub key_order: bool,
    /// An invite grant needs its level as an invite on its path's last edge (spec/permissions.md
    /// §2, along one path: notes/write-path-design.md §1, Edge writes). False (control
    /// `-invite-role`): a role there suffices, so any writer grants.
    pub invite_check: bool,
    /// A lowering is judged, and audits, when it takes its edge as restored down in role or in
    /// invite, dropping the writes whose need the edge no longer meets (an invite grant falls with
    /// a writer's edge). False (control `-admin-falls`): only a fall from admin is judged.
    pub any_fall: bool,
    /// A purge request holds the author right over a delta only where its own chain ([signer,
    /// path..]) holds the delta's purge author (notes/write-path-design.md §1, What a purger must
    /// hold). False (control `-purge-any-path`): its path giving write on the thing suffices.
    pub purge_chain: bool,
    /// A request by author matches the deltas naming exactly that purge author. False (control
    /// `-purge-contains`): every delta whose chain holds it.
    pub purge_exact: bool,
    /// Proposed (notes/path-form.md, Whom a write is by; not in `fixed`): a write may name the
    /// thing it writes as its purge author (on the wire its path lists that thing last), and a
    /// request's chain holds the thing it is on, so any valid request by that author takes it.
    /// False: a delta naming its own thing has no author a request's chain holds.
    pub author_thing: bool,
    /// The variant `-facts`, not the design: a carried write is judged by its own facts (signer,
    /// `ts`, path, ID), a valid cover only standing in for its body, which closes the window a
    /// cover by a writer not yet holding a removal opens but makes every snapshot state those
    /// facts per carried commit. False (the rule, spec/permissions.md §5.2 Copies, §5.3): a valid
    /// cover's copy of a write shows it whatever the write's own validity.
    pub cover_facts: bool,
    /// In a commit of several edge writes, a lowering's `keeps` passes over the drops of the
    /// commit's lowerings applied before it too (spec/commits.md §2). False (control
    /// `-own-drops`): over its own drops alone.
    pub commit_drops: bool,
    /// `keeps(L)` also needs the remaining admin edge L relies on (its last edge, else the named
    /// holder's) to stay a standing admin past L's drops; else L is void. False (control
    /// `-remains-unkept`): the last-admin rule reads the pass before L's drops alone.
    pub remains_kept: bool,
    /// A path's last edge (the default remaining admin) is its final hop where that joins its
    /// last member to the thing written in one edge; a descent of two steps or more has none.
    /// False (control `-last-any`): the edge (Ak, T), read whether or not it is a hop.
    pub last_hop: bool,
    /// Which held writes are dispute candidates.
    pub candidates: Candidates,
    /// A trusted write's seeds are the writes resting on its edge whose need there its own value
    /// does not meet, as its audit reads them (a demotion to write keeps the invites under it).
    /// False (control `-seeds-all`): every unlisted write resting on its edge.
    pub seeds_by_need: bool,
    /// Control (`-refuse-shapes`): a commit of several edge writes carrying a self-removal or a
    /// part on an edge of its own stated path applies nowhere. False (the rule): it is judged part
    /// by part like any (`World::commit`), so a single-use link redemption (an invite grant and its
    /// signer's own leave) applies.
    pub refuse_shapes: bool,
    /// How a write putting an end on a standing admin edge (or shortening its end) is judged.
    pub until: Until,
    /// What a counting vouch's entry keeps of the commit it names.
    pub entry: Entry,
    /// Honest writing in `Sim` (a policy, not a judging rule; `Rules::remake`): a witness of a
    /// removed party's role write that the removal dropped makes the write again as its own, where
    /// it holds the right to (`Sim::remake_at`).
    pub remake: bool,
    /// Purge rights by class (notes/a1-spec/permissions.md §6, *taken*): a request holds, over each
    /// delta it names, each member of the delta's retention set it holds: `admin` where it is valid
    /// as a delta needing admin along its path, `writer` as one needing write, `author` as one
    /// needing write whose chain holds the delta's purge author; every selector (`Names`) read.
    /// False (`fixed`): the `author` class alone, by author alone, retention unread.
    pub purge_classes: bool,
    /// A request reaches the writes a valid cover shows of a commit the node does not hold (spec/
    /// commits.md §5 Purge, Without the header: judged by the facts the cover states, here the
    /// commit's own). False (`fixed`): held deltas alone.
    pub purge_copies: bool,
    /// OPEN-proposed: an addendum vouches for a purge request as for content, by a writer holding
    /// the role the class needs (admin for `admin`). False (*taken*, spec/permissions.md §6 today):
    /// no addendum vouches for one.
    pub purge_addenda: bool,
    /// Variant (`-purge-at-key`, "gone means gone"): a request holds a role iff its path gives it
    /// at its key; no later cut takes the right.
    pub purge_at_key: bool,
    /// A cover marked as its writer's own cover is also valid, where its path gave write just
    /// before it, while an explicit lowering the timeline applies (whatever it takes from its edge
    /// at this node), signed by its writer, ordered at or after it, names it
    /// (notes/a1-spec/permissions.md §5.2 Own cover, *taken*), whatever cuts its path later. False:
    /// judged as any cover.
    pub own_cover: bool,
    /// What a drop takes of the commit it drops a part of (notes/a1-spec/README.md Open 23: a
    /// single-use redemption's grant and its leave).
    pub drops: Drops,
}

/// What a drop (a lowering's audit, a trusted write's seeds) takes of a commit (Open 23).
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Drops {
    /// The rule (`fixed`): a commit's edge-class parts on one thing fall together. A part another
    /// part of its commit on the same thing would be dropped beside (put in question and not
    /// listed) is dropped with it, as a list keeps a commit whole: the redemption's leave falls
    /// with its grant, so the link stays with the redemption the sharer listed.
    Commit,
    /// Control (`-part-drops`): each part alone, by its own need: a redemption whose grant falls
    /// keeps its leave (its need at the link's edge is admin, never met by a read grant), so a
    /// forged earlier redemption the sharer never saw burns the link for the one it saw.
    Part,
    /// Variant (`-leave-lowers`, rejected: fails `safety N` in 26 more of the gate's 13,000 random
    /// worlds): as `Part`, a leave's need at the edge it lowers being that the edge gives more
    /// than it sets, so any lowering leaving it out drops it.
    LeaveLowers,
    /// Variant (`-leave-on-grant`): as `Part`, and a leave of edge h is dropped with its commit's
    /// other parts stating h as their path's last edge (a link's grant).
    LeaveOnGrant,
    /// Variant (`-redemption-whole`, a carve-out for links): as `Part`, and a lowering of h leaving
    /// out a commit holding a leave of h and a part stating h as its path's last edge drops it whole.
    Redemption,
}

/// What a counting vouch entry keeps of the commit `c` it names (notes/a1-spec/permissions.md
/// §5.1 Vouches): a vouch on thing N applies where its voucher's path gives admin on N, so it
/// speaks for N alone.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Entry {
    /// The rule: c's parts on the vouch's own thing, as an addendum keeps content on its own
    /// thing. A commit writing several things needs a vouch on each.
    OnThing,
    /// Control (`-vouch-whole`): c whole, its parts on every thing it writes, so authority on N
    /// keeps a part on another thing no holder of that thing vouched for.
    Whole,
}

/// An **end**: a write giving an edge that gives admin at its `ts` a value giving admin until an
/// earlier end (an `until` after its `ts`; the edge standing, or ending later). How it is judged
/// (notes/path-model-findings.md 38).
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Until {
    /// The rule: a grant, no lowering; the last-admin rule alone reads it (taking a standing admin's
    /// standing). It applies in a pass only where its path gives admin there.
    Plain,
    /// Variant (`-until-at-key`): a lowering judged at its key (verdict, audit, frontier, dispute
    /// candidate), whose drops are the writes resting on its edge whose need there its value does
    /// not meet at their own `ts`. Every write before it in key order is stamped before the end,
    /// so it drops nothing, seeds nothing and its trust never changes a reading: its one effect is
    /// the verdict, so it applies for good where its author's standing falls later.
    AtKey,
    /// Variant (`-until-past-end`, as the end "a lowering at the time it names" reads literally):
    /// as `AtKey`, its drops and seeds also the held writes after it in key order resting on its
    /// edge, stamped at or past the end, that its list does not name (whatever sets the edge
    /// between). Fails liveness: drops only grow, so what it drops stays dropped after it falls.
    PastEnd,
}

/// The dispute candidates (`disputes`): held edge writes of another holder's edge giving it below
/// admin at their `ts`, but finalizes, and of those:
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Candidates {
    /// Every one: self-removals (a holder thing's leave by its member) and invite grants included.
    All,
    /// Explicit writes only: no self-removal, and none the walk trusting it applies as an invite
    /// grant (neither carries a frontier, so neither is ever trusted).
    Explicit,
}

impl Rules {
    /// The first round's reading of the notes, simplest: the findings are its failures.
    pub fn design() -> Rules {
        Rules {
            vouch: Vouch::Off,
            regrant: Regrant::FirstApplied,
            exempt_chain: false,
            last_admin: LastAdmin::AnyEdge,
            no_own_addendum: false,
            no_own_vouch: false,
            evidence_leaves: false,
            rewrite: false,
            leave_in_question: false,
            self_void: false,
            audit_held: false,
            stands: false,
            key_order: false,
            invite_check: true,
            any_fall: true,
            purge_chain: true,
            purge_exact: true,
            author_thing: false,
            cover_facts: false,
            commit_drops: true,
            remains_kept: false,
            last_hop: false,
            candidates: Candidates::All,
            seeds_by_need: false,
            refuse_shapes: false,
            until: Until::Plain,
            entry: Entry::Whole,
            remake: false,
            purge_classes: false,
            purge_copies: false,
            purge_addenda: false,
            purge_at_key: false,
            own_cover: false,
            drops: Drops::Part,
        }
    }
    /// The design: every fix the notes state, a removal judged in the world its list makes
    /// (notes/write-path-design.md §1) included.
    pub fn fixed() -> Rules {
        Rules {
            vouch: Vouch::BaseWalk,
            regrant: Regrant::FirstChained,
            exempt_chain: false,
            last_admin: LastAdmin::Named,
            no_own_addendum: true,
            no_own_vouch: true,
            evidence_leaves: true,
            rewrite: true,
            leave_in_question: true,
            self_void: true,
            audit_held: true,
            stands: true,
            key_order: false,
            invite_check: true,
            any_fall: true,
            purge_chain: true,
            purge_exact: true,
            author_thing: false,
            cover_facts: false,
            commit_drops: true,
            remains_kept: true,
            last_hop: true,
            candidates: Candidates::Explicit,
            seeds_by_need: true,
            refuse_shapes: false,
            until: Until::Plain,
            entry: Entry::OnThing,
            remake: false,
            purge_classes: false,
            purge_copies: false,
            purge_addenda: false,
            purge_at_key: false,
            own_cover: false,
            drops: Drops::Commit,
        }
    }
    /// The proposal (README.md, Paths, Making again; notes/role-remake-model.md): nothing vouches
    /// for a role write (a vouch is inert), and a witness of a removed party's role write that the
    /// removal dropped makes it again as its own write, judged by its own path at its own key.
    pub fn remake() -> Rules {
        Rules { vouch: Vouch::Off, remake: true, ..Rules::fixed() }
    }
    /// `fixed` with the purge readings the draft takes (notes/a1-spec/permissions.md §5.2 Own
    /// cover, §6; notes/purge-model.md): rights by class, requests reaching copies, own covers
    /// standing with their removal. Off in `fixed` while the walk (osis-perm `paths`) owes them.
    pub fn purging() -> Rules {
        Rules { purge_classes: true, purge_copies: true, own_cover: true, ..Rules::fixed() }
    }
    /// `remake` with the same purge readings.
    pub fn purging_remake() -> Rules {
        Rules { purge_classes: true, purge_copies: true, own_cover: true, ..Rules::remake() }
    }
    /// A lowering (`World::lowers`), and under `Until::AtKey`/`PastEnd` a write giving admin until
    /// an end after its `ts` (`World::ends`): judged where it takes its edge down, a dispute
    /// candidate, carrying a frontier.
    pub fn lowering(&self, w: &World, i: Id) -> Option<Edge> {
        w.lowers(i).or_else(|| if self.until == Until::Plain { None } else { w.ends(i) })
    }
}

/// The role a value gives at `ts`.
pub fn alive(v: Val, ts: u32) -> Role {
    if v.1.is_some_and(|u| u <= ts) {
        Role::None
    } else {
        v.0
    }
}

/// A standing admin edge's value: admin, no `until` (`timed`: or an `until` later than `ts`).
fn standing(v: Option<Val>, ts: u32, timed: bool) -> bool {
    v.is_some_and(|v| v.0 == Role::Admin && if timed { alive(v, ts) == Role::Admin } else { v.1.is_none() })
}

#[derive(Clone, Debug, Default)]
pub struct World {
    pub records: Vec<Edge>,
    pub commits: Vec<Commit>,
}

impl World {
    /// Record edges, each admin.
    pub fn new(records: &[Edge]) -> World {
        World { records: records.to_vec(), commits: vec![] }
    }
    /// A commit; its hops are read from its stated path once, here (`World::hops`).
    pub fn push(&mut self, signer: Thing, ts: u32, path: &[Thing], on: Thing, kind: Kind) -> Id {
        self.push_marked(signer, ts, path, on, kind, &[])
    }
    /// `push` with the hops `direct` (by index: hop 0 joins the signer to the first member after
    /// it) marked direct: joined by their direct edge though the first is a mint ancestor of the
    /// second (notes/a1-spec/permissions.md §1 Path, Direct mark; spec/wire.md §4 `marks`). A mark
    /// is allowed only on a hop otherwise read as a descent of two steps or more; on any other
    /// (no record chain between them, a one-step descent whose record edge is the direct edge, a
    /// position past the members) the part applies nowhere, as a member named twice does.
    pub fn push_marked(&mut self, signer: Thing, ts: u32, path: &[Thing], on: Thing, mut kind: Kind, direct: &[usize]) -> Id {
        let mut all = vec![signer];
        all.extend(path);
        // the path's end decides the class: an edge write whose path ends at the holder is a
        // self-removal; any other ends at the thing written
        let leave = matches!(&kind, Kind::Edge { holder, .. } if all.last() == Some(holder));
        if !leave {
            all.push(on);
        }
        // a finalize is a shape (spec/permissions.md §2 Finalize): a frontier-less removal of
        // another holder's grant that is no self-removal; the flag marks only the frontier's absence
        if let Kind::Edge { holder, finalize, .. } = &mut kind {
            *finalize = *finalize && !leave && *holder != signer;
        }
        let marks_ok = direct.iter().all(|&k| k + 1 < all.len() && self.joins(all[k], all[k + 1]).len() >= 2);
        let well = all.iter().collect::<BTreeSet<_>>().len() == all.len() && marks_ok;
        let hops = if well { all.windows(2).enumerate().flat_map(|(k, p)| if direct.contains(&k) { vec![(p[0], p[1])] } else { self.joins(p[0], p[1]) }).collect() } else { vec![] };
        let i = self.commits.len();
        self.commits.push(Commit { signer, ts, path: path.to_vec(), on, kind, hops, well, leave, pa: 0, ret: Retention::AuthorOrAdmin, own: false, cid: i, own_path: false, direct: direct.to_vec() });
        i
    }
    /// One commit of several edge writes on `on` along one path (spec/commits.md §2). Its parts
    /// take effect in holder order, but the parts on the stated path's last thing or final hop (a
    /// self-removal of its last thing, as in a single-use link redemption, or the record edge a
    /// descent ends with; neither changes the other's path) last. Two parts on one holder's edge are
    /// bad input, applying nowhere (the `roles.0` delta's map keys would repeat: spec/data-model.md
    /// deterministic CBOR).
    pub fn commit(&mut self, signer: Thing, ts: u32, path: &[Thing], on: Thing, parts: Vec<Kind>) -> Vec<Id> {
        self.commit_marked(signer, ts, path, on, parts, &[])
    }
    /// `commit` with the hops `direct` marked direct (`push_marked`).
    pub fn commit_marked(&mut self, signer: Thing, ts: u32, path: &[Thing], on: Thing, mut parts: Vec<Kind>, direct: &[usize]) -> Vec<Id> {
        let ak = *path.last().unwrap_or(&signer);
        let last = if direct.contains(&path.len()) { Some((ak, on)) } else { self.joins(ak, on).last().copied() };
        parts.sort_by_key(|k| match k {
            Kind::Edge { holder, .. } => (*holder == ak || last == Some((*holder, on)), *holder),
            _ => panic!("a commit of several parts carries edge writes"),
        });
        let ids: Vec<Id> = parts.into_iter().map(|k| self.push_marked(signer, ts, path, on, k, direct)).collect();
        self.group(&ids);
        ids
    }
    /// Makes `ids` (consecutive in key order, as `commit` orders them) one commit.
    pub fn group(&mut self, ids: &[Id]) {
        let cid = ids[0];
        let sets: Vec<Edge> = ids.iter().filter_map(|&i| self.sets(i)).collect();
        let hops: BTreeSet<Edge> = ids.iter().flat_map(|&i| self.hops(i).to_vec()).collect();
        let twice = sets.iter().collect::<BTreeSet<_>>().len() < sets.len();
        let own_path = ids.iter().any(|&i| self.leave(i)) || sets.iter().any(|e| hops.contains(e));
        for &i in ids {
            self.commits[i].cid = cid;
            self.commits[i].own_path = own_path;
            if twice {
                self.commits[i].well = false;
                self.commits[i].hops.clear();
            }
        }
    }
    /// The commit part `i` belongs to.
    pub fn cid(&self, i: Id) -> Id {
        self.commits[i].cid
    }
    /// The number of parts of commit `cid`.
    pub fn parts(&self, cid: Id) -> usize {
        self.commits.iter().filter(|c| c.cid == cid).count()
    }
    /// The parts of commit `cid`.
    pub fn part_ids(&self, cid: Id) -> impl Iterator<Item = Id> + '_ {
        (0..self.commits.len()).filter(move |&i| self.commits[i].cid == cid)
    }
    /// The mint admin of `t`: the holder of its record edge.
    fn mint_of(&self, t: Thing) -> Option<Thing> {
        self.records.iter().find(|e| e.1 == t).map(|e| e.0)
    }
    /// The edges joining consecutive path members `p`, `q`: by descent (the record edges down the
    /// mint chain) where `p` is a mint ancestor of `q`, else their direct edge.
    fn joins(&self, p: Thing, q: Thing) -> Vec<Edge> {
        let mut down = vec![];
        let mut t = q;
        while let Some(m) = self.mint_of(t) {
            down.push((m, t));
            if m == p {
                down.reverse();
                return down;
            }
            if down.len() > self.records.len() {
                break;
            }
            t = m;
        }
        vec![(p, q)]
    }
    pub fn content(&mut self, signer: Thing, ts: u32, path: &[Thing], on: Thing) -> Id {
        self.push(signer, ts, path, on, Kind::Content)
    }
    /// Content stating `ix` (into [signer, path..]) as its purge author.
    pub fn content_as(&mut self, signer: Thing, ts: u32, path: &[Thing], on: Thing, ix: usize) -> Id {
        let i = self.content(signer, ts, path, on);
        self.authored(i, ix);
        i
    }
    /// `ix` one past the path names the thing written (`Rules::author_thing`).
    pub fn authored(&mut self, i: Id, ix: usize) {
        assert!(ix <= self.commits[i].path.len() + 1, "a purge author index past the thing written is bad input");
        self.commits[i].pa = ix;
    }
    /// One content commit as the header states it (notes/path-form.md, One path): ONE path
    /// [A1..Ak] and purge-author index for every thing in `on`. A thing that is the path's last
    /// is written along the path ending at it (its part's path is the stated one less that
    /// thing); every other thing is one hop past the path's end. The index reads into
    /// [signer, A1..Ak] for every part, so one naming Ak names, on Ak's own part, the thing
    /// written.
    pub fn stated(&mut self, signer: Thing, ts: u32, path: &[Thing], ix: usize, on: &[Thing]) -> Vec<Id> {
        assert!(ix <= path.len(), "a purge author index past the path is bad input");
        on.iter()
            .map(|&t| {
                let own = if path.last() == Some(&t) { &path[..path.len() - 1] } else { path };
                self.content_as(signer, ts, own, t, ix)
            })
            .collect()
    }
    /// One content commit in the split form (notes/path-form.md, The split form): each thing in
    /// `parts` with its own path, one purge author `author` for the commit, a member of every
    /// thing's members ([signer, A1..Ak, thing]). Its parts are one commit (a list naming it names
    /// them all), each judged along its own path.
    pub fn split(&mut self, signer: Thing, ts: u32, author: Thing, parts: &[(&[Thing], Thing)]) -> Vec<Id> {
        let ids: Vec<Id> = parts
            .iter()
            .map(|&(path, on)| {
                let ix = std::iter::once(signer).chain(path.iter().copied()).chain([on]).position(|m| m == author);
                self.content_as(signer, ts, path, on, ix.expect("the purge author is a member of every thing's path"))
            })
            .collect();
        self.group(&ids);
        ids
    }
    /// A purge request by `author` on `on`, along `path`.
    pub fn purge(&mut self, signer: Thing, ts: u32, path: &[Thing], on: Thing, author: Thing) -> Id {
        self.push(signer, ts, path, on, Kind::purge(author))
    }
    /// A purge request naming `names` on `on`, along `path`.
    pub fn request(&mut self, signer: Thing, ts: u32, path: &[Thing], on: Thing, names: Names) -> Id {
        self.push(signer, ts, path, on, Kind::Purge { names })
    }
    /// Sets who may purge content `i`.
    pub fn retain(&mut self, i: Id, r: Retention) {
        self.commits[i].ret = r;
    }
    /// Marks cover `i` as its writer's own cover.
    pub fn own_cover(&mut self, i: Id) {
        assert!(matches!(self.commits[i].kind, Kind::Cover { .. }), "only a cover is an own cover");
        self.commits[i].own = true;
    }
    /// [signer, path..]: the things a commit acts as.
    pub fn chain(&self, i: Id) -> Vec<Thing> {
        let c = &self.commits[i];
        std::iter::once(c.signer).chain(c.path.iter().copied()).collect()
    }
    /// The thing a commit names as its purge author: of [signer, path..], or the thing written.
    pub fn purge_author(&self, i: Id) -> Thing {
        self.chain(i).get(self.commits[i].pa).copied().unwrap_or(self.commits[i].on)
    }
    /// A frontier listing `ids`, cut per thing.
    pub fn cut(&self, ids: &[Id]) -> BTreeMap<Thing, Set> {
        let mut f: BTreeMap<Thing, Set> = BTreeMap::new();
        for &i in ids {
            f.entry(self.commits[i].on).or_default().insert(i);
        }
        f
    }
    /// An edge write setting `holder`'s edge on `on`, standing; `frontier` is cut per thing.
    pub fn edge(&mut self, signer: Thing, ts: u32, path: &[Thing], on: Thing, holder: Thing, role: Role, frontier: &[Id]) -> Id {
        let f = self.cut(frontier);
        self.push(signer, ts, path, on, Kind::set(holder, role).listing(f))
    }
    pub fn addendum(&mut self, signer: Thing, ts: u32, path: &[Thing], on: Thing, removal: Id, list: &[Id]) -> Id {
        self.push(signer, ts, path, on, Kind::Addendum { removal, list: list.iter().copied().collect() })
    }
    pub fn vouch(&mut self, signer: Thing, ts: u32, path: &[Thing], on: Thing, removal: Id, list: &[Id]) -> Id {
        self.push(signer, ts, path, on, Kind::Vouch { removal, list: list.iter().copied().collect() })
    }
    pub fn edit(&mut self, i: Id, f: impl FnOnce(Kind) -> Kind) {
        let k = std::mem::replace(&mut self.commits[i].kind, Kind::Content);
        self.commits[i].kind = f(k);
    }
    pub fn mark_adminless(&mut self, i: Id) {
        self.edit(i, |k| k.with(|_, _, _, a| *a = true));
    }
    pub fn set_until(&mut self, i: Id, t: u32) {
        self.edit(i, |k| k.until(t));
    }
    /// Names `holder` as the remaining admin edge write `i` relies on.
    pub fn rely(&mut self, i: Id, holder: Thing) {
        self.edit(i, |k| k.relying(holder));
    }
    pub fn key(&self, i: Id) -> Key {
        (self.commits[i].ts, self.commits[i].signer, i)
    }
    /// A content-class commit's position: the start of its `ts`.
    pub fn pos(&self, i: Id) -> Key {
        (self.commits[i].ts, 0, 0)
    }
    /// The edges a commit's stated path uses; none for a path naming a thing twice (bad input).
    pub fn hops(&self, i: Id) -> &[Edge] {
        &self.commits[i].hops
    }
    /// A path naming no thing twice (else bad input: the commit applies nowhere).
    pub fn well(&self, i: Id) -> bool {
        self.commits[i].well
    }
    /// A self-removal: an edge write whose stated path ends at the holder of the edge it sets.
    pub fn leave(&self, i: Id) -> bool {
        self.commits[i].leave
    }
    pub fn edge_class(&self, i: Id) -> bool {
        matches!(self.commits[i].kind, Kind::Edge { .. } | Kind::Vouch { .. })
    }
    /// The edge an edge write sets.
    pub fn sets(&self, i: Id) -> Option<Edge> {
        match &self.commits[i].kind {
            Kind::Edge { holder, .. } => Some((*holder, self.commits[i].on)),
            _ => None,
        }
    }
    /// An edge write setting its edge to below admin at its own `ts`, but a finalize (which ends
    /// a grant already ended).
    pub fn lowers(&self, i: Id) -> Option<Edge> {
        match &self.commits[i].kind {
            Kind::Edge { holder, role, until, finalize: false, .. } if alive((*role, *until), self.commits[i].ts) < Role::Admin => Some((*holder, self.commits[i].on)),
            _ => None,
        }
    }
    /// An edge write giving admin until an end after its own `ts` (no self-removal): it lowers
    /// where its edge gave admin ending later, or standing.
    pub fn ends(&self, i: Id) -> Option<Edge> {
        match &self.commits[i].kind {
            Kind::Edge { holder, role: Role::Admin, until: Some(u), finalize: false, .. } if *u > self.commits[i].ts && !self.leave(i) => Some((*holder, self.commits[i].on)),
            _ => None,
        }
    }
    /// `r`'s frontier names `j` in some leaf (notes/a1-spec/permissions.md §5.1: a list names a
    /// part whose commit's ID is in it, so an entry names every part of its commit).
    fn in_frontier(&self, r: Id, j: Id) -> bool {
        self.in_leaves(r, j, None)
    }
    /// `r`'s frontier names `j` in a leaf for one of `leaves` (None: any leaf).
    fn in_leaves(&self, r: Id, j: Id, leaves: Option<&Things>) -> bool {
        match &self.commits[r].kind {
            Kind::Edge { frontier, .. } => frontier.iter().any(|(t, l)| leaves.is_none_or(|s| s.contains(t)) && l.iter().any(|&c| self.names(c, j))),
            _ => false,
        }
    }
    /// A list entry `c` names commit `j`: it is `j`'s commit, or a cover carrying `j`.
    pub fn names(&self, c: Id, j: Id) -> bool {
        self.cid(c) == self.cid(j) || matches!(&self.commits[c].kind, Kind::Cover { carries } if carries.contains(&j))
    }
    /// The honest frontier of a lowering of `edge`: every commit resting on it (through it, or a
    /// self-removal of it) that `received`.
    pub fn through(&self, edge: Edge, received: impl Fn(Id) -> bool) -> Vec<Id> {
        (0..self.commits.len()).filter(|&i| received(i) && (self.hops(i).contains(&edge) || (self.leave(i) && self.sets(i) == Some(edge)))).collect()
    }
}

/// What a node judges from: the commits it holds, the frontier leaves it sees (None: every
/// leaf), its trust set.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct View {
    pub held: Set,
    pub leaves: Option<Things>,
    pub trust: Set,
}

impl View {
    pub fn all(w: &World) -> View {
        View { held: (0..w.commits.len()).collect(), leaves: None, trust: Set::new() }
    }
    pub fn trusting(mut self, t: &[Id]) -> View {
        self.trust = t.iter().copied().collect();
        self
    }
    pub fn trusting_also(mut self, r: Id) -> View {
        self.trust.insert(r);
        self
    }
    pub fn without(mut self, drop: &[Id]) -> View {
        for i in drop {
            self.held.remove(i);
        }
        self
    }
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Reading {
    /// Edge-class commits the settled walk applies.
    pub applied: Set,
    /// Applied edge writes that lowered their edge.
    pub lowered: Set,
    /// Edge writes the settled walk applies as invite grants.
    pub invited: Set,
    /// Valid content-class commits.
    pub valid: Set,
    /// Held content a valid purge request holding the right over it names.
    pub purged: Set,
    /// Writes shown only by a valid cover's copy (none under `Rules::cover_facts`).
    pub copied: Set,
    /// Final roles, every `until` counted removed, and the invite each edge gives in the end.
    pub roles: BTreeMap<Edge, Role>,
    pub invites: BTreeMap<Edge, Role>,
    /// The settled walk's edge writes per edge (key, value), and its cuts: the applied explicit
    /// lowerings taking an edge from write or above to below (edge, key), which content judges by.
    pub hist: BTreeMap<Edge, Vec<(Key, Val)>>,
    pub cuts: BTreeSet<(Edge, Key)>,
    /// The settled walk's edge values, and the first walk's (no vouch counting).
    pub state: BTreeMap<Edge, Val>,
    pub first: BTreeMap<Edge, Val>,
    /// Vouches counting (applied in the first walk after their removal), addenda vouching
    /// (valid, their writer holding write at their key).
    pub counting: Set,
    pub vouching: Set,
    /// The entries of the counting vouches.
    entries: Vouched,
    pub dropped: Set,
    /// Commits of several parts whose own drops took their path's authority (`Walk::self_taken`).
    pub self_taken: Set,
    /// What dropped each dropped commit: the lowering whose audit did, or the trusted write
    /// whose seeds did.
    pub dropper: BTreeMap<Id, Id>,
    /// Trusted writes the settled walk does not apply.
    pub void: Set,
    /// Lowerings judged void (their own drops would take their authority) and not dropped later.
    pub voided: Set,
    /// Dropped commits whose drop the reading does not justify: the dropper is not applied (or,
    /// for a seed, not trusted and applied), is no explicit lowering ordered after the commit, the
    /// commit does not rest on the edge it lowers, or its list names the commit. Checked from the
    /// reading alone (`unjustified`), apart from how the walk reached it.
    pub stray: Set,
    /// Restarts (one per applying lowering that dropped something, and one per round of void
    /// trusted writes), passes walked, edge-class commits visited from each pass's restart point
    /// on, and setters read by the void checks (`keeps`), over the whole reading.
    pub rounds: u32,
    pub passes: u64,
    pub walked: u64,
    pub checked: u64,
    /// The vouch iteration did not settle (`Vouch::SameWalk`).
    pub circle: bool,
}

impl Reading {
    pub fn role(&self, holder: Thing, target: Thing) -> Role {
        self.roles.get(&(holder, target)).copied().unwrap_or(Role::None)
    }
    /// A commit shows: valid content, or an applied edge-class commit.
    pub fn shows(&self, i: Id) -> bool {
        self.valid.contains(&i) || self.applied.contains(&i) || self.copied.contains(&i)
    }
    /// What users observe of the reading: what each holder can do (its role and
    /// invite in the end, and the role each edge gives at the start of each `ts`, which content
    /// written there rests on, with the cuts) and which content counts (valid, copied, purged).
    /// Which edge-class commits apply is not in it: an applied write changing none of this is
    /// seen by nobody (notes/path-model-findings.md 33).
    pub fn observed(&self, w: &World) -> Observed {
        let last = w.commits.iter().map(|c| c.ts).max().unwrap_or(0) + 1;
        let edges: BTreeSet<Edge> = self.hist.keys().chain(&w.records).copied().collect();
        let at = |e: Edge, t: u32| {
            let rec = if w.records.contains(&e) { (Role::Admin, None) } else { (Role::None, None) };
            alive(self.hist.get(&e).and_then(|h| h.iter().rev().find(|(k, _)| k.0 < t)).map_or(rec, |x| x.1), t)
        };
        let timeline = edges.into_iter().map(|e| (e, (0..=last).map(|t| at(e, t)).collect::<Vec<Role>>())).filter(|(_, r)| r.iter().any(|&r| r > Role::None)).collect();
        let some = |m: &BTreeMap<Edge, Role>| m.iter().filter(|(_, r)| **r > Role::None).map(|(&e, &r)| (e, r)).collect();
        Observed { roles: some(&self.roles), invites: some(&self.invites), timeline, cuts: self.cuts.clone(), valid: self.valid.clone(), copied: self.copied.clone(), purged: self.purged.clone() }
    }
}

/// `Reading::observed`.
#[derive(Clone, Debug, PartialEq)]
pub struct Observed {
    pub roles: BTreeMap<Edge, Role>,
    pub invites: BTreeMap<Edge, Role>,
    pub timeline: BTreeMap<Edge, Vec<Role>>,
    pub cuts: BTreeSet<(Edge, Key)>,
    pub valid: Set,
    pub copied: Set,
    pub purged: Set,
}

#[derive(Clone, Debug)]
struct Low {
    id: Id,
    /// An explicit write (it audits, and cuts the content through its edge before it).
    explicit: bool,
    edge: Edge,
    before: Role,
    after: Role,
}

#[derive(Clone, Default)]
struct Pass {
    state: BTreeMap<Edge, Val>,
    /// The edge as restored: the highest role each edge held since the last explicit write on it
    /// (values an `until` or a self-removal took included).
    restored: BTreeMap<Edge, Role>,
    /// Each edge's invite field, and its invite as restored (as `restored`, of `invite_at`).
    inv: BTreeMap<Edge, Role>,
    rinv: BTreeMap<Edge, Role>,
    hist: BTreeMap<Edge, Vec<(Key, Val)>>,
    applied: Vec<Id>,
    /// The applied invite grants (attributed to invite, not to admin: spec/permissions.md §5.1
    /// step 3, admin before invite).
    invited: Set,
    lows: Vec<Low>,
}

impl Pass {
    fn at(&self, e: Edge, ts: u32) -> Role {
        self.state.get(&e).map_or(Role::None, |&v| alive(v, ts))
    }
    /// The invite edge `e` gives at `ts`: every invite where it gives admin, else its invite
    /// field, at most its role.
    fn invite_at(&self, e: Edge, ts: u32) -> Role {
        give_invite(self.at(e, ts), self.inv.get(&e).copied().unwrap_or(Role::None))
    }
}

/// The invite a value gives: every invite at admin, else its field at most its role.
fn give_invite(role: Role, field: Role) -> Role {
    if role == Role::Admin {
        Role::Admin
    } else {
        field.min(role)
    }
}

/// What a write needs of one edge of its path: a role there, or (the last edge of an invite
/// grant's path) an invite there.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Need {
    Role(Role),
    Invite(Role),
    /// More than this role or this invite (a leave's need at the edge it lowers, `Drops::LeaveLowers`).
    Above(Role, Role),
}

impl Need {
    fn met(self, role: Role, invite: Role) -> bool {
        match self {
            Need::Role(r) => role >= r,
            Need::Invite(r) => invite >= r,
            Need::Above(r, i) => role > r || invite > i,
        }
    }
}

/// An edge write adding a grant below admin (no self-removal, no finalize): one that may apply
/// as an invite grant. Its level is its role (its invite is at most its role).
fn invite_grant(w: &World, i: Id) -> Option<Role> {
    let c = &w.commits[i];
    match &c.kind {
        Kind::Edge { role, until, invite, finalize: false, .. } if !c.leave && *invite <= *role && alive((*role, *until), c.ts) > Role::None && *role < Role::Admin => Some(*role),
        _ => None,
    }
}

/// What write `i` needs of edge `e` (where its path holds `e`; a self-removal of `e` needs admin
/// there): admin, unless it is an invite grant (`as_invite`: applied as one, or, for a held write
/// this pass did not apply, one that may), which needs its level as a role on its path's edges
/// before the last and as an invite on the last (`Rules::invite_check`; else as a role there too).
fn need(w: &World, rules: &Rules, i: Id, e: Edge, as_invite: bool) -> Need {
    let hops = w.hops(i);
    // a leave applies at the edge it lowers by that edge giving more than it sets
    if rules.drops == Drops::LeaveLowers && w.leave(i) && w.sets(i) == Some(e) {
        if let Kind::Edge { role, until, invite, .. } = &w.commits[i].kind {
            let a = alive((*role, *until), w.commits[i].ts);
            return Need::Above(a, give_invite(a, *invite));
        }
    }
    match (as_invite, invite_grant(w, i)) {
        (true, Some(r)) if rules.invite_check && hops.last() == Some(&e) => Need::Invite(r),
        (true, Some(r)) => Need::Role(r),
        _ if matches!(w.commits[i].kind, Kind::Edge { finalize: true, .. }) => Need::Role(Role::Write),
        _ => Need::Role(Role::Admin),
    }
}

struct Walk {
    pass: Pass,
    dropped: Set,
    /// Commits of several parts whose path, once the commit took effect in the pass that judged
    /// a part of it, did not keep admin past the drops its parts made there.
    self_taken: Set,
    dropper: BTreeMap<Id, Id>,
    voided: Set,
    rounds: u32,
    passes: u64,
    walked: u64,
    checked: u64,
}

/// (removal, commit, thing) triples counting vouches keep, by commit ID: the parts of the commit
/// on the thing (`Rules::entry`).
type Vouched = BTreeSet<(Id, Id, Thing)>;

/// R's list names `j`: its frontier, in a leaf the node sees, or a counting vouch against it
/// keeping `j`'s thing.
fn listed(w: &World, v: &View, vouched: &Vouched, r: Id, j: Id) -> bool {
    w.in_leaves(r, j, v.leaves.as_ref()) || vouched.contains(&(w.cid(r), w.cid(j), w.commits[j].on))
}

/// What vouch `i`'s entries keep (it counting against the removal's edge writes on `lowered`, the
/// edges the first walk applies them on as lowerings): each listed role write on its own thing
/// whose commit rests there on one of those edges by a part on that thing (a removal's write
/// void in the first walk keeps nothing by a vouch, though another write of its commit counts),
/// not its own signer's under `no_own_vouch`, kept on that thing (`Entry::OnThing`) or on every
/// thing its commit writes (`Entry::Whole`).
fn entries(w: &World, rules: &Rules, i: Id, lowered: &[Edge]) -> Vouched {
    let Kind::Vouch { removal, list } = &w.commits[i].kind else { return Vouched::new() };
    let on = w.commits[i].on;
    let own = |j: Id| rules.no_own_vouch && w.commits[j].signer == w.commits[i].signer;
    let rests = |j: Id| w.part_ids(w.cid(j)).any(|x| w.commits[x].on == on && lowered.iter().any(|&h| rests_on(w, rules, x, h)));
    let mut out = Vouched::new();
    for &j in list.iter().filter(|&&j| w.edge_class(j) && w.commits[j].on == on && !own(j) && rests(j)) {
        let (r, c) = (w.cid(*removal), w.cid(j));
        match rules.entry {
            Entry::OnThing => {
                out.insert((r, c, on));
            }
            Entry::Whole => out.extend(w.part_ids(c).map(|p| (r, c, w.commits[p].on))),
        }
    }
    out
}

/// Control `exempt_chain`: the grants R's own authority rests on, as the held writes give them:
/// those giving admin on an edge of its path, and so on along their paths.
fn chain(w: &World, held: &Set, r: Id) -> Set {
    let mut edges: BTreeSet<Edge> = w.hops(r).iter().copied().collect();
    let mut out = Set::new();
    loop {
        let gives = |j: Id| matches!(&w.commits[j].kind, Kind::Edge { role: Role::Admin, .. });
        let more: Vec<Id> = held.iter().copied().filter(|&j| !out.contains(&j) && w.key(j) < w.key(r) && gives(j) && w.sets(j).is_some_and(|e| edges.contains(&e))).collect();
        if more.is_empty() {
            return out;
        }
        for j in more {
            edges.extend(w.hops(j));
            out.insert(j);
        }
    }
}

/// Whether a lowering of edge `e` puts commit `j` in question: its path holds `e`, or (with
/// `leave_in_question`) it is a self-removal of `e`.
fn rests_on(w: &World, rules: &Rules, j: Id, e: Edge) -> bool {
    w.hops(j).contains(&e) || (rules.leave_in_question && w.leave(j) && w.sets(j) == Some(e))
}

/// The parts lowering `r` of edge `e` drops beside `q` (its drops, each unlisted) under
/// `Rules::drops`, of `cands` (the held edge-class parts it may drop: ordered before it, not
/// dropped, not void): `Commit` (for seeds; the walk's audit reads it in `gone`), every part on the
/// same thing of a commit it drops a part of; `Grant`, the leaves
/// resting on a dropped part (of its commit, lowering the edge that part's path ends with);
/// `Redemption`, the commits it does not list holding a leave of `e` and a part whose path ends
/// with `e`, whole.
fn widen(w: &World, rules: &Rules, v: &View, vouched: &Vouched, r: Id, e: Edge, cands: &[Id], q: &Set) -> Set {
    let mut out = Set::new();
    let other = |j: Id| w.cid(j) != w.cid(r) && !q.contains(&j) && !listed(w, v, vouched, r, j);
    match rules.drops {
        Drops::Part | Drops::LeaveLowers => {}
        Drops::Commit => {
            let cids: BTreeSet<(Id, Thing)> = q.iter().map(|&j| (w.cid(j), w.commits[j].on)).collect();
            out.extend(cands.iter().copied().filter(|&j| cids.contains(&(w.cid(j), w.commits[j].on)) && other(j)));
        }
        Drops::LeaveOnGrant => {
            for &j in q {
                let Some(&h) = w.hops(j).last() else { continue };
                out.extend(cands.iter().copied().filter(|&l| w.cid(l) == w.cid(j) && w.leave(l) && w.sets(l) == Some(h) && other(l)));
            }
        }
        Drops::Redemption => {
            let redemption = |c: Id| w.part_ids(c).any(|x| w.leave(x) && w.sets(x) == Some(e)) && w.part_ids(c).any(|x| !w.leave(x) && w.hops(x).last() == Some(&e));
            out.extend(cands.iter().copied().filter(|&j| redemption(w.cid(j)) && other(j)));
        }
    }
    out
}

fn order(w: &World, held: &Set) -> Vec<Id> {
    let mut o: Vec<Id> = held.iter().copied().filter(|&i| w.edge_class(i)).collect();
    o.sort_by_key(|&i| w.key(i));
    o
}

/// The last-admin rule for edge write `i` setting `e` to `new` against `p`: None where it refuses
/// the write; else the remaining admin edge it relies on, where it relies on one.
fn remains(w: &World, rules: &Rules, p: &Pass, i: Id, e: Edge, new: Val) -> Option<Option<Edge>> {
    let c = &w.commits[i];
    let Kind::Edge { relies, adminless, .. } = &c.kind else { return Some(None) };
    if *adminless {
        return Some(None);
    }
    let old = p.state.get(&e).copied();
    match rules.last_admin {
        LastAdmin::Off => Some(None),
        LastAdmin::AnyEdge => {
            let refuses = p.at(e, c.ts) == Role::Admin && alive(new, c.ts) < Role::Admin && !p.state.keys().any(|&k| k.1 == c.on && k != e && p.at(k, c.ts) == Role::Admin);
            (!refuses).then_some(None)
        }
        LastAdmin::Named | LastAdmin::NamedTimed => {
            let timed = rules.last_admin == LastAdmin::NamedTimed;
            if !standing(old, c.ts, timed) || standing(Some(new), c.ts, timed) {
                return Some(None);
            }
            let ok = |x: Edge| x != e && standing(p.state.get(&x).copied(), c.ts, timed);
            // the last edge: the final hop where it joins Ak (the signer for an empty path) to the
            // thing in one edge (`last_hop`; else (Ak, T) wherever it is)
            let ak = *c.path.last().unwrap_or(&c.signer);
            let last = if rules.last_hop { w.hops(i).last().copied().filter(|&h| h == (ak, c.on)) } else { Some((ak, c.on)) };
            if let Some(l) = last.filter(|&l| ok(l)) {
                return Some(Some(l));
            }
            relies.map(|n| (n, c.on)).filter(|&x| ok(x)).map(Some)
        }
    }
}

/// A lowering's verdict, given the first time a pass reaches it holding the right (its path
/// giving admin, the last-admin rule passed) and taking its edge from admin, as restored, to
/// below; kept for the rest of the walk. One that does not hold the right, or takes nothing (its
/// edge below admin already), has no verdict and is walked like any write: a restart reaching it
/// judges it again.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Verdict {
    Applied,
    /// Its own drops would take its authority: it does not apply and drops nothing.
    Void,
}

/// Whether write `i`, applied in `p`, still holds the right its path needs at its key once the
/// writes `gone` names are dropped: each edge of its path keeps admin (`setter_keeps`). No later
/// write is read and nothing is walked again: the cost is the setters read.
fn keeps(w: &World, p: &Pass, gone: &dyn Fn(Id) -> bool, i: Id, memo: &mut BTreeMap<Id, bool>, checked: &mut u64) -> bool {
    if let Some(&k) = memo.get(&i) {
        return k;
    }
    let (key, ts) = (w.key(i), w.commits[i].ts);
    let ok = w.hops(i).iter().all(|&e| setter_keeps(w, p, gone, e, key, &|v| alive(v, ts) == Role::Admin, memo, checked));
    memo.insert(i, ok);
    ok
}

/// Edge `e` read back along the applied writes setting it before `key`, latest first, skipping
/// those gone, grants that do not keep in turn, and self-removals `accept` passes (a self-removal
/// lowers, so it passes only where the edge before it did): the first left decides by `accept`
/// (a lowering as it stands; a self-removal it refuses), a record edge at the bottom.
#[allow(clippy::too_many_arguments)]
fn setter_keeps(w: &World, p: &Pass, gone: &dyn Fn(Id) -> bool, e: Edge, key: Key, accept: &dyn Fn(Val) -> bool, memo: &mut BTreeMap<Id, bool>, checked: &mut u64) -> bool {
    for &(k, v) in p.hist.get(&e).into_iter().flatten().rev().filter(|x| x.0 < key) {
        *checked += 1;
        let j = k.2;
        if gone(j) {
            continue;
        }
        // a self-removal lowers: the edge after it gives what `accept` asks only where the edge
        // before it did, so one that would pass is read through (notes/path-model-findings.md 43)
        if w.leave(j) {
            if accept(v) {
                continue;
            }
            return false;
        }
        if w.lowers(j).is_some() || keeps(w, p, gone, j, memo, checked) {
            return accept(v);
        }
    }
    w.records.contains(&e)
}

/// The walk from the seeds `d0` (notes/write-path-design.md §1): edge-class commits in key
/// order, skipping D. A lowering is judged the first time a pass reaches it holding its right and
/// taking its edge from admin (`Verdict`), and keeps that verdict: in every later pass an applied
/// one applies unjudged and unaudited, a void one is skipped. An applied lowering whose audit drops something adds its drops to D and restarts
/// the walk from the earliest of them, once; the commits before that point replay unchanged and
/// are not counted in `walked`.
fn walk(w: &World, rules: &Rules, v: &View, d0: &Set, vouched: &Vouched) -> Walk {
    let order = order(w, &v.held);
    let pos: BTreeMap<Id, usize> = order.iter().enumerate().map(|(k, &i)| (i, k)).collect();
    let mut dropped = d0.clone();
    let mut dropper = BTreeMap::new();
    let mut self_taken = Set::new();
    let mut verdict: BTreeMap<Id, Verdict> = BTreeMap::new();
    let (mut rounds, mut passes, mut walked, mut checked, mut from) = (0, 0, 0, 0, 0);
    loop {
        passes += 1;
        let mut p = Pass::default();
        for &e in &w.records {
            p.state.insert(e, (Role::Admin, None));
            p.restored.insert(e, Role::Admin);
            p.rinv.insert(e, Role::Admin);
        }
        let mut restart = None;
        // the commit taking effect: its ID, the drops its parts made in this pass and its parts
        // judged applied in this pass
        let mut cur: Option<Id> = None;
        let mut cdrops = Set::new();
        let mut judged_here: Vec<Id> = vec![];
        // once a commit has taken effect: the pass ends where its parts dropped something
        // (a restart only where a drop is before `at`, the next commit: drops after it, past an
        // end (`Until::PastEnd`), are skipped when reached)
        let mut taken = |p: &Pass, cdrops: &Set, judged_here: &[Id], cid: Id, at: usize| -> Option<usize> {
            if cdrops.is_empty() {
                return None;
            }
            if !judged_here.is_empty() && w.parts(cid) > 1 {
                let gone = |j: Id| cdrops.contains(&j);
                if judged_here.iter().any(|&l| !keeps(w, p, &gone, l, &mut BTreeMap::new(), &mut 0)) {
                    self_taken.insert(cid);
                }
            }
            cdrops.iter().map(|j| pos[j]).min().filter(|&r| r < at)
        };
        for (k, &i) in order.iter().enumerate() {
            let cid = w.cid(i);
            if cur != Some(cid) {
                if let Some(prev) = cur {
                    if let Some(r) = taken(&p, &cdrops, &judged_here, prev, k) {
                        restart = Some(r);
                        break;
                    }
                }
                cur = Some(cid);
                cdrops.clear();
                judged_here.clear();
            }
            if dropped.contains(&i) {
                continue;
            }
            if k >= from {
                walked += 1;
            }
            let c = &w.commits[i];
            let lowering = rules.lowering(w, i).is_some() && !w.leave(i);
            let judged = if lowering { verdict.get(&i).copied() } else { None };
            // how it applies: by admin along its path (or its verdict), as an invite grant, or as
            // a finalize (spec/permissions.md §2, along its stated path)
            let mut as_invite = false;
            let mut as_finalize = false;
            match judged {
                // applied for good where it lowers; where its edge as restored in this pass is below
                // its value, in role or invite, it would raise the edge: it applies there only as
                // any write does, by admin along its path (finding 27)
                Some(Verdict::Applied) => {
                    if let Kind::Edge { holder, role, until, invite, .. } = &c.kind {
                        let e = (*holder, c.on);
                        let after = alive((*role, *until), c.ts);
                        let raises = after > p.restored.get(&e).copied().unwrap_or(Role::None).max(p.at(e, c.ts))
                            || give_invite(after, *invite) > p.rinv.get(&e).copied().unwrap_or(Role::None).max(p.invite_at(e, c.ts));
                        if raises && !w.hops(i).iter().all(|&h| p.at(h, c.ts) == Role::Admin) {
                            continue;
                        }
                    }
                }
                Some(Verdict::Void) => continue,
                None => {
                    if !w.well(i) || (rules.refuse_shapes && w.commits[i].own_path) {
                        continue;
                    }
                    let hops = w.hops(i);
                    let path_role = hops.iter().map(|&e| p.at(e, c.ts)).min().unwrap_or(Role::Admin);
                    match &c.kind {
                        Kind::Edge { holder, finalize: true, .. } => {
                            // it ends a grant past its `until`, by a writer holding a role at
                            // least the grant's; else it applies nothing
                            let old = p.state.get(&(*holder, c.on)).copied();
                            let ended = old.is_some_and(|v| v.0 > Role::None && v.1.is_some_and(|u| u <= c.ts));
                            if !(ended && path_role >= old.map_or(Role::None, |v| v.0).max(Role::Write)) {
                                continue;
                            }
                            as_finalize = true;
                        }
                        _ if path_role == Role::Admin => {}
                        Kind::Edge { holder, .. } => {
                            // an invite grant: a holder with no current grant, its level within
                            // the path's invite (roles before the last edge, the last's invite)
                            let Some(lvl) = invite_grant(w, i) else { continue };
                            let (last, before) = hops.split_last().expect("a grant states a hop");
                            let gives = if rules.invite_check { p.invite_at(*last, c.ts) } else { p.at(*last, c.ts) };
                            if p.at((*holder, c.on), c.ts) > Role::None || !before.iter().all(|&e| p.at(e, c.ts) >= lvl) || gives < lvl {
                                continue;
                            }
                            as_invite = true;
                        }
                        _ => continue,
                    }
                }
            }
            let Kind::Edge { holder, role, until, invite, .. } = &c.kind else {
                p.applied.push(i);
                continue;
            };
            let e = (*holder, c.on);
            let new = (*role, *until);
            let leave = w.leave(i);
            // an explicit write: attributed to admin (spec/permissions.md §5.1 step 2); a
            // self-removal, an invite grant and a finalize are not, and audit nothing
            let explicit = !leave && !as_invite && !as_finalize;
            // the last-admin rule, with the commit's earlier parts in effect
            let relied = if judged.is_none() && !as_invite && !as_finalize {
                match remains(w, rules, &p, i, e, new) {
                    None => continue,
                    Some(r) => r,
                }
            } else {
                None
            };
            let old = p.state.get(&e).copied().unwrap_or((Role::None, None));
            // a self-removal only lowers: it removes the grant, or sets no component (role, invite,
            // `until`) above the grant's
            let old_inv = p.inv.get(&e).copied().unwrap_or(Role::None);
            if leave && new.0 > Role::None && (new.0 > old.0 || *invite > old_inv || old.1.is_some_and(|u| new.1.is_none_or(|n| n > u))) {
                continue;
            }
            let restored = p.restored.get(&e).copied().unwrap_or(Role::None).max(p.at(e, c.ts));
            let rinv = p.rinv.get(&e).copied().unwrap_or(Role::None).max(p.invite_at(e, c.ts));
            let (before, after) = (if explicit { restored } else { p.at(e, c.ts) }, alive(new, c.ts));
            let after_inv = give_invite(after, *invite);
            // an explicit write audits against the edge as restored, once, when judged: where it
            // takes the edge down (`any_fall`: in role or invite; else from admin)
            let falls = if rules.any_fall { restored > after || rinv > after_inv } else { restored == Role::Admin && after < Role::Admin };
            // or it puts an end on admin (`Until`): the edge gives admin at its `ts`, standing or
            // ending after the end it sets
            let falls = falls || (rules.until != Until::Plain && explicit && w.ends(i).is_some() && alive(old, c.ts) == Role::Admin && old.1.is_none_or(|o| new.1.is_some_and(|u| u < o)));
            // the value it sets as the write at `t` needs it (`Until::Plain`: as at its own `ts`)
            let at = |t: u32| {
                let a = if rules.until == Until::Plain { after } else { alive(new, t) };
                (a, give_invite(a, *invite))
            };
            let mut q = vec![];
            if judged.is_none() && explicit && falls {
                let exempt = if rules.exempt_chain { chain(w, &v.held, i) } else { Set::new() };
                // in question: a write resting on the edge whose need there the edge as restored
                // met and its new value does not, of another commit (no list can name its own)
                let alone = |j: Id| {
                    let n = need(w, rules, j, e, p.invited.contains(&j) || !p.applied.contains(&j));
                    let (a, ai) = at(w.commits[j].ts);
                    w.cid(j) != c.cid && rests_on(w, rules, j, e) && !exempt.contains(&j) && !listed(w, v, vouched, i, j) && n.met(restored, rinv) && !n.met(a, ai)
                };
                // `Drops::Commit`: with another part of its commit on its thing, not dropped or void
                let gone = |j: Id| {
                    alone(j)
                        || (rules.drops == Drops::Commit
                            && w.cid(j) != c.cid
                            && w.part_ids(w.cid(j)).any(|x| x != j && w.commits[x].on == w.commits[j].on && !dropped.contains(&x) && verdict.get(&x) != Some(&Verdict::Void) && alone(x)))
                };
                // `Until::PastEnd`: the held writes after it resting on its edge whose need there its
                // value met at its own `ts` and does not at theirs (stamped at or past its end)
                let past = |j: Id| {
                    let n = need(w, rules, j, e, true);
                    let (a, ai) = at(w.commits[j].ts);
                    past_end(w, rules, i, j) && w.cid(j) != c.cid && rests_on(w, rules, j, e) && !exempt.contains(&j) && !listed(w, v, vouched, i, j) && n.met(after, after_inv) && !n.met(a, ai)
                };
                // in question: the applied writes before it (`audit_held`: the held ones not yet
                // dropped or void) resting on its edge
                let before = || -> Vec<Id> {
                    if rules.audit_held {
                        order[..k].iter().copied().filter(|j| !dropped.contains(j) && verdict.get(j) != Some(&Verdict::Void)).collect()
                    } else {
                        p.applied.clone()
                    }
                };
                // void: its drops, with those of its commit's lowerings applied before it
                // (`commit_drops`), would take its authority (read back from the state, before any
                // drop is listed), or the remaining admin it relies on (`remains_kept`)
                let all_gone = |j: Id| gone(j) || (rules.commit_drops && cdrops.contains(&j));
                if rules.self_void {
                    let mut memo = BTreeMap::new();
                    let timed = rules.last_admin == LastAdmin::NamedTimed;
                    let kept = keeps(w, &p, &all_gone, i, &mut memo, &mut checked)
                        && relied.is_none_or(|r| !rules.remains_kept || setter_keeps(w, &p, &all_gone, r, w.key(i), &|v| standing(Some(v), c.ts, timed), &mut memo, &mut checked));
                    if !kept {
                        verdict.insert(i, Verdict::Void);
                        continue;
                    }
                }
                let cands = before();
                q = cands.iter().copied().filter(|&j| gone(j)).collect();
                let more = if rules.drops == Drops::Commit { Set::new() } else { widen(w, rules, v, vouched, i, e, &cands, &q.iter().copied().collect()) };
                q.extend(more);
                q.extend(order[k + 1..].iter().copied().filter(|&j| !dropped.contains(&j) && past(j)));
                verdict.insert(i, Verdict::Applied);
                judged_here.push(i);
            }
            p.state.insert(e, new);
            p.inv.insert(e, *invite);
            if explicit {
                p.restored.insert(e, new.0);
                p.rinv.insert(e, after_inv);
            } else if as_invite {
                let r = p.restored.entry(e).or_insert(Role::None);
                *r = (*r).max(new.0);
                let r = p.rinv.entry(e).or_insert(Role::None);
                *r = (*r).max(after_inv);
                p.invited.insert(i);
            }
            p.hist.entry(e).or_default().push((w.key(i), new));
            p.applied.push(i);
            if after < before {
                p.lows.push(Low { id: i, explicit, edge: e, before, after });
            }
            for j in q {
                dropped.insert(j);
                dropper.insert(j, i);
                cdrops.insert(j);
            }
        }
        if restart.is_none() {
            if let Some(prev) = cur {
                restart = taken(&p, &cdrops, &judged_here, prev, order.len());
            }
        }
        if let Some(r) = restart {
            (from, rounds) = (r, rounds + 1);
            continue;
        }
        let voided = verdict.iter().filter(|(i, x)| **x == Verdict::Void && !dropped.contains(*i)).map(|(i, _)| *i).collect();
        return Walk { pass: p, dropped, dropper, self_taken, voided, rounds, passes, walked, checked };
    }
}

/// A trusted write's seeds: each held edge-class commit ordered before it, resting on its edge,
/// that its list does not name and (`seeds_by_need`) whose need there its value does not meet,
/// with the trusted write that drops it.
fn seeds(w: &World, rules: &Rules, v: &View, active: &Set, vouched: &Vouched) -> BTreeMap<Id, Id> {
    let mut d = BTreeMap::new();
    for &r in active {
        let (Some(h), Kind::Edge { role, until, invite, .. }) = (w.sets(r), &w.commits[r].kind) else { continue };
        let after = alive((*role, *until), w.commits[r].ts);
        let after_inv = give_invite(after, *invite);
        let exempt = if rules.exempt_chain { chain(w, &v.held, r) } else { Set::new() };
        for &j in &v.held {
            // its value as `j` needs it (`Until::Plain`: as at its own `ts`)
            let a = if rules.until == Until::Plain { after } else { alive((*role, *until), w.commits[j].ts) };
            let n = || need(w, rules, j, h, true);
            let unmet = || !rules.seeds_by_need || !n().met(a, give_invite(a, *invite));
            // before it, or (`Until::PastEnd`) after it and past its end
            let when = if w.key(j) < w.key(r) { unmet() } else { past_end(w, rules, r, j) && n().met(after, after_inv) && !n().met(a, give_invite(a, *invite)) };
            if w.edge_class(j) && w.cid(j) != w.cid(r) && rests_on(w, rules, j, h) && !exempt.contains(&j) && !listed(w, v, vouched, r, j) && when {
                d.entry(j).or_insert(r);
            }
        }
        let cands: Vec<Id> = v.held.iter().copied().filter(|&j| w.edge_class(j) && w.key(j) < w.key(r)).collect();
        let mine: Set = d.iter().filter(|(_, x)| **x == r).map(|(j, _)| *j).collect();
        for j in widen(w, rules, v, vouched, r, h, &cands, &mine) {
            d.entry(j).or_insert(r);
        }
    }
    d
}

/// Under `Until::PastEnd`, `j` is stamped at or past the end lowering `r` sets.
fn past_end(w: &World, rules: &Rules, r: Id, j: Id) -> bool {
    rules.until == Until::PastEnd && w.ends(r).is_some() && matches!(w.commits[r].kind, Kind::Edge { until: Some(u), .. } if w.commits[j].ts >= u)
}

/// The vouches a walk applies after their removal, where it applies an edge write of that
/// removal as a lowering (an explicit write: no self-removal, invite grant or finalize;
/// notes/a1-spec/permissions.md §5.1 Vouches), and the (removal, role write) pairs they name.
fn counting(w: &World, rules: &Rules, wk: &Walk) -> (Set, Vouched) {
    let (mut ids, mut out) = (Set::new(), Vouched::new());
    let lowers = |a: Id| rules.lowering(w, a).is_some() && !w.leave(a) && !wk.pass.invited.contains(&a);
    for &i in &wk.pass.applied {
        if let Kind::Vouch { removal, .. } = &w.commits[i].kind {
            let lowered: Vec<Edge> = wk.pass.applied.iter().copied().filter(|&a| w.cid(a) == w.cid(*removal) && lowers(a)).filter_map(|a| w.sets(a)).collect();
            if w.key(*removal) < w.key(i) && !lowered.is_empty() {
                ids.insert(i);
                out.extend(entries(w, rules, i, &lowered));
            }
        }
    }
    (ids, out)
}

/// The settled walk under the active trusted writes (its rounds and passes counting every walk
/// made), the seeds with their trusted writes, the first walk's state, the counting vouches, and
/// whether the vouches settled.
fn settle(w: &World, rules: &Rules, v: &View, active: &Set) -> (Walk, BTreeMap<Id, Id>, BTreeMap<Edge, Val>, Set, Vouched, bool) {
    let none = Vouched::new();
    let (mut rounds, mut passes, mut walked, mut checked) = (0, 0, 0, 0);
    let mut run = |vouched: &Vouched| {
        let d0 = seeds(w, rules, v, active, vouched);
        let mut wk = walk(w, rules, v, &d0.keys().copied().collect(), vouched);
        rounds += wk.rounds;
        passes += wk.passes;
        walked += wk.walked;
        checked += wk.checked;
        (wk.rounds, wk.passes, wk.walked, wk.checked) = (rounds, passes, walked, checked);
        (wk, d0)
    };
    match rules.vouch {
        Vouch::Off => {
            let (wk, d0) = run(&none);
            let first = wk.pass.state.clone();
            (wk, d0, first, Set::new(), Vouched::new(), false)
        }
        Vouch::BaseWalk => {
            let base = run(&none).0;
            let (ids, vouched) = counting(w, rules, &base);
            let (wk, d0) = run(&vouched);
            (wk, d0, base.pass.state, ids, vouched, false)
        }
        Vouch::SameWalk => {
            let mut seen = vec![none.clone()];
            let mut vouched = none;
            loop {
                let (wk, d0) = run(&vouched);
                let (ids, next) = counting(w, rules, &wk);
                if next == vouched || seen.contains(&next) {
                    let circle = next != vouched;
                    let first = wk.pass.state.clone();
                    return (wk, d0, first, ids, next, circle);
                }
                seen.push(next.clone());
                vouched = next;
            }
        }
    }
}

fn role_at(w: &World, p: &Pass, e: Edge, pos: Key) -> Role {
    let rec = if w.records.contains(&e) { (Role::Admin, None) } else { (Role::None, None) };
    alive(p.hist.get(&e).and_then(|h| h.iter().rev().find(|(k, _)| *k < pos)).map_or(rec, |x| x.1), pos.0)
}

/// The first key after which every edge gives write in the settled walk (KEY0: from the start).
fn first_applied(w: &World, p: &Pass, edges: &[Edge]) -> Option<Key> {
    let mut keys: Vec<Key> = vec![(0, 0, 0)];
    keys.extend(edges.iter().filter_map(|e| p.hist.get(e)).flatten().map(|x| x.0));
    keys.sort();
    keys.into_iter().find(|k| edges.iter().all(|&e| role_at(w, p, e, (k.0, k.1, k.2 + 1)) >= Role::Write))
}

/// Per edge, the key of the first chained write giving it `at` or above (spec/permissions.md
/// §4 Chained writes, along the write's stated path, `until` disregarded).
fn first_chained(w: &World, held: &Set, at: Role) -> BTreeMap<Edge, Key> {
    let mut max: BTreeMap<Edge, Role> = w.records.iter().map(|&e| (e, Role::Admin)).collect();
    let mut inv: BTreeMap<Edge, Role> = w.records.iter().map(|&e| (e, Role::Admin)).collect();
    let mut first: BTreeMap<Edge, Key> = w.records.iter().map(|&e| (e, (0, 0, 0))).collect();
    let get = |m: &BTreeMap<Edge, Role>, e: &Edge| m.get(e).copied().unwrap_or(Role::None);
    for i in order(w, held) {
        let hops = w.hops(i);
        let (Some(e), Kind::Edge { role, invite, finalize, .. }) = (w.sets(i), &w.commits[i].kind) else { continue };
        // a self-removal and a finalize set no edge here (spec/permissions.md §4 Chained writes)
        if !w.well(i) || w.leave(i) || *finalize {
            continue;
        }
        // by admin on its target, or by an invite there for an invite grant
        let admin = hops.iter().all(|h| get(&max, h) == Role::Admin);
        let invited = invite_grant(w, i).is_some_and(|lvl| hops.split_last().is_some_and(|(l, b)| get(&inv, l) >= lvl && b.iter().all(|h| get(&max, h) >= lvl)));
        if !admin && !invited {
            continue;
        }
        if *role >= at {
            first.entry(e).or_insert(w.key(i));
        }
        let m = max.entry(e).or_insert(Role::None);
        *m = (*m).max(*role);
        let m = inv.entry(e).or_insert(Role::None);
        *m = (*m).max(give_invite(*role, *invite));
    }
    first
}

/// The final role of each edge, every `until` counted removed.
fn finals(p: &Pass) -> BTreeMap<Edge, Role> {
    p.state.iter().map(|(&e, &(r, u))| (e, if u.is_some() { Role::None } else { r })).collect()
}

/// The commits a node judges: those it holds, and under `Rules::cover_facts` those a held cover
/// carries (judged by the facts the cover states, its body forgotten or never received, where the
/// cover is valid). Under copies a node judges only the commits it holds; a carried one shows by
/// the cover's copy.
fn known(w: &World, rules: &Rules, v: &View) -> Set {
    let mut k = v.held.clone();
    for &c in v.held.iter().filter(|_| rules.cover_facts) {
        if let Kind::Cover { carries } = &w.commits[c].kind {
            k.extend(carries);
        }
    }
    k
}

/// Valid content-class commits, and the addenda among them that vouch.
fn content(w: &World, rules: &Rules, v: &View, p: &Pass) -> (Set, Set) {
    let chained = first_chained(w, &v.held, Role::Write);
    let fin = finals(p);
    let none = Vouched::new();
    let vouches = |a: Id| w.hops(a).iter().all(|&e| role_at(w, p, e, w.pos(a)) >= Role::Write);
    let mut valid = Set::new();
    loop {
        let mut next = Set::new();
        let known = known(w, rules, v);
        for &i in known.iter().filter(|&&i| !w.edge_class(i)) {
            let hops = w.hops(i);
            // a write not held is judged by the facts a valid cover carrying it states; carried
            // only by covers that are not valid it counts as never received
            let stated = v.held.contains(&i) || valid.iter().any(|&c| matches!(&w.commits[c].kind, Kind::Cover { carries } if carries.contains(&i)));
            if !w.well(i) || !stated {
                continue;
            }
            let pos = w.pos(i);
            // an own cover stands while an explicit lowering by its writer naming it applies,
            // whatever it takes from its edge where this node holds it, its path having given the
            // role just before it (§5.2 Own cover)
            let lowering = |l: Id| w.lowers(l).is_some() && !w.leave(l) && !p.invited.contains(&l);
            if rules.own_cover
                && w.commits[i].own
                && hops.iter().all(|&e| role_at(w, p, e, pos) >= Role::Write)
                && p.applied.iter().any(|&l| lowering(l) && w.commits[l].signer == w.commits[i].signer && w.key(l) >= pos && listed(w, v, &none, l, i))
            {
                next.insert(i);
                continue;
            }
            let cuts: Vec<&Low> = p.lows.iter().filter(|l| l.explicit && hops.contains(&l.edge) && l.before >= Role::Write && l.after < Role::Write).collect();
            let held = hops.iter().all(|&e| role_at(w, p, e, pos) >= Role::Write);
            let ok = (held && !cuts.iter().any(|l| w.key(l.id) > pos))
                || cuts.iter().any(|l| listed(w, v, &none, l.id, i))
                // an addendum vouches for no purge request (spec/permissions.md §6)
                || valid.iter().any(|&a| match &w.commits[a].kind {
                    Kind::Addendum { removal, list } if !matches!(w.commits[i].kind, Kind::Purge { .. }) => {
                        w.commits[a].on == w.commits[i].on
                            && list.iter().any(|&c| w.names(c, i))
                            && !(rules.no_own_addendum && w.commits[a].signer == w.commits[i].signer)
                            && cuts.iter().any(|l| l.id == *removal && w.key(l.id) > pos && w.key(l.id) < w.pos(a))
                            && vouches(a)
                    }
                    _ => false,
                })
                || (hops.iter().all(|e| fin.get(e).is_some_and(|r| *r >= Role::Write)) && {
                    let from = match rules.regrant {
                        Regrant::FirstApplied => first_applied(w, p, &hops),
                        Regrant::FirstChained => hops.iter().map(|e| chained.get(e).copied()).collect::<Option<Vec<Key>>>().and_then(|k| k.into_iter().max()),
                    };
                    from.is_some_and(|k| k == (0, 0, 0) || pos > k)
                });
            if ok {
                next.insert(i);
            }
        }
        if next == valid {
            let vouching = valid.iter().copied().filter(|&a| matches!(w.commits[a].kind, Kind::Addendum { .. }) && vouches(a)).collect();
            return (valid, vouching);
        }
        valid = next;
    }
}

/// The content a valid purge request holds a right over (notes/a1-spec/permissions.md §6). Under
/// `purge_classes` each named delta is judged alone, by the members of its retention set the request
/// holds (`holds`); else by the `author` class alone (a request by author P, valid, holds the right
/// over the earlier deltas on its thing whose purge author is exactly P, P on its chain). Under
/// `purge_copies` the writes a valid cover shows of a commit not held (`copied`) are named too.
fn purges(w: &World, rules: &Rules, v: &View, p: &Pass, valid: &Set, copied: &Set) -> Set {
    let mut out = Set::new();
    let mut cands: Set = v.held.iter().copied().filter(|&d| matches!(w.commits[d].kind, Kind::Content)).collect();
    if rules.purge_copies {
        cands.extend(copied.iter().copied().filter(|&d| matches!(w.commits[d].kind, Kind::Content)));
    }
    for &q in &v.held {
        let Kind::Purge { names } = w.commits[q].kind else { continue };
        let (on, ts) = (w.commits[q].on, w.commits[q].ts);
        let named = |d: Id| {
            let c = &w.commits[d];
            c.on == on
                && match names {
                    Names::Author(a) => c.ts < ts && if rules.purge_exact { w.purge_author(d) == a } else { w.chain(d).contains(&a) },
                    Names::Aspect => c.ts < ts,
                    Names::Commit(j) => w.cid(j) == w.cid(d) && c.ts < ts,
                    Names::Destroy => true,
                }
        };
        // the author class: the request's chain holds the delta's purge author
        let on_chain = |d: Id| !rules.purge_chain || w.chain(q).contains(&w.purge_author(d)) || (rules.author_thing && w.purge_author(d) == on);
        if !rules.purge_classes {
            let Names::Author(a) = names else { continue };
            if !valid.contains(&q) || (rules.purge_chain && !w.chain(q).contains(&a) && !(rules.author_thing && a == on)) {
                continue;
            }
            out.extend(cands.iter().copied().filter(|&d| named(d)));
            continue;
        }
        let destroy = names == Names::Destroy;
        let admin = holds(w, rules, v, p, valid, q, Role::Admin, destroy);
        // a destruction holds the `admin` right alone (`created.0` is purgeable by admin)
        let write = !destroy && holds(w, rules, v, p, valid, q, Role::Write, false);
        out.extend(cands.iter().copied().filter(|&d| {
            named(d)
                && (admin
                    || (write
                        && match w.commits[d].ret {
                            Retention::Admin => false,
                            Retention::AuthorOrAdmin => on_chain(d),
                            Retention::Writer => true,
                        }))
        }));
    }
    out
}

/// Whether request `q` holds role `r` on its thing (notes/a1-spec/permissions.md §6: exactly when a
/// delta of it needing `r`, along its path, at its key would be valid, spec §5.2): its path gave
/// `r` just before its position and no cut of its path below `r` is ordered after it; else a
/// cut's list names it, a valid addendum by a holder of `r` against such a cut names it
/// (`purge_addenda`), or the path is re-granted for `r`. A destruction's right reads no cut on an
/// edge into its own thing stamped after it. Under `purge_at_key` the first clause's role alone.
#[allow(clippy::too_many_arguments)]
fn holds(w: &World, rules: &Rules, v: &View, p: &Pass, valid: &Set, q: Id, r: Role, destroy: bool) -> bool {
    let hops = w.hops(q);
    if !w.well(q) {
        return false;
    }
    let (pos, on) = (w.pos(q), w.commits[q].on);
    let at = hops.iter().all(|&e| role_at(w, p, e, pos) >= r);
    if rules.purge_at_key {
        return at;
    }
    let cuts: Vec<&Low> = p.lows.iter().filter(|l| l.explicit && hops.contains(&l.edge) && l.before >= r && l.after < r && !(destroy && l.edge.1 == on && w.key(l.id) > pos)).collect();
    let none = Vouched::new();
    let gives = |a: Id| w.hops(a).iter().all(|&e| role_at(w, p, e, w.pos(a)) >= r);
    (at && !cuts.iter().any(|l| w.key(l.id) > pos))
        || cuts.iter().any(|l| listed(w, v, &none, l.id, q))
        || (rules.purge_addenda
            && valid.iter().any(|&a| match &w.commits[a].kind {
                Kind::Addendum { removal, list } => {
                    w.commits[a].on == on
                        && list.iter().any(|&c| w.names(c, q))
                        && !(rules.no_own_addendum && w.commits[a].signer == w.commits[q].signer)
                        && cuts.iter().any(|l| l.id == *removal && w.key(l.id) > pos && w.key(l.id) < w.pos(a))
                        && gives(a)
                }
                _ => false,
            }))
        || {
            let fin = finals(p);
            let chained = first_chained(w, &v.held, r);
            hops.iter().all(|e| fin.get(e).is_some_and(|x| *x >= r))
                && hops.iter().map(|e| chained.get(e).copied()).collect::<Option<Vec<Key>>>().and_then(|k| k.into_iter().max()).is_some_and(|k| k == (0, 0, 0) || pos > k)
        }
}

/// A node's reading: a function of the world's rules, what it holds, the leaves it sees and
/// its trust set.
pub fn judge(w: &World, rules: &Rules, v: &View) -> Reading {
    let mut active: Set = v.trust.iter().copied().filter(|i| v.held.contains(i) && w.sets(*i).is_some()).collect();
    let mut void = Set::new();
    let (mut rounds, mut passes, mut walked, mut checked) = (0, 0, 0, 0);
    loop {
        let (wk, d0, first, counting, entries, circle) = settle(w, rules, v, &active);
        rounds += wk.rounds;
        passes += wk.passes;
        walked += wk.walked;
        checked += wk.checked;
        let applied: Set = wk.pass.applied.iter().copied().collect();
        let gone: Vec<Id> = active.iter().copied().filter(|r| !applied.contains(r)).collect();
        if !gone.is_empty() {
            rounds += 1;
            for r in gone {
                active.remove(&r);
                void.insert(r);
            }
            continue;
        }
        let (valid, vouching) = content(w, rules, v, &wk.pass);
        let copied = if !rules.cover_facts {
            valid.iter().filter_map(|&c| match &w.commits[c].kind { Kind::Cover { carries } => Some(carries.iter().copied().filter(|j| !valid.contains(j))), _ => None }).flatten().collect()
        } else {
            Set::new()
        };
        let purged = purges(w, rules, v, &wk.pass, &valid, &copied);
        let mut dropper = wk.dropper;
        dropper.extend(d0);
        let fin = finals(&wk.pass);
        let mut rd = Reading {
            lowered: wk.pass.lows.iter().map(|l| l.id).collect(),
            invited: wk.pass.invited.clone(),
            valid,
            purged,
            copied,
            invites: fin.iter().map(|(&e, &r)| (e, give_invite(r, wk.pass.inv.get(&e).copied().unwrap_or(Role::None)))).collect(),
            roles: fin,
            hist: wk.pass.hist.clone(),
            cuts: wk.pass.lows.iter().filter(|l| l.explicit && l.before >= Role::Write && l.after < Role::Write).map(|l| (l.edge, w.key(l.id))).collect(),
            state: wk.pass.state.clone(),
            first,
            counting,
            entries,
            vouching,
            applied,
            dropped: wk.dropped,
            self_taken: wk.self_taken,
            dropper,
            void,
            voided: wk.voided,
            stray: Set::new(),
            rounds,
            passes,
            walked,
            checked,
            circle,
        };
        rd.stray = unjustified(w, rules, v, &rd);
        return rd;
    }
}

/// The dropped commits whose drop the reading does not justify (`Reading::stray`): read from
/// the reading's applied set, trust set, lists and counting vouches alone.
fn unjustified(w: &World, rules: &Rules, v: &View, rd: &Reading) -> Set {
    let vouched = &rd.entries;
    rd.dropped
        .iter()
        .copied()
        .filter(|&j| {
            let Some(&r) = rd.dropper.get(&j) else { return true };
            let seed = v.trust.contains(&r) && !rd.void.contains(&r);
            let Some(h) = w.sets(r) else { return true };
            let lowering = seed || (rules.lowering(w, r).is_some() && !w.leave(r));
            !(rd.applied.contains(&r) && lowering && (w.key(j) < w.key(r) || past_end(w, rules, r, j)) && rests_on(w, rules, j, h) && !listed(w, v, vouched, r, j))
        })
        .collect()
}

/// Disputes: the candidates (`Candidates`: held edge writes of another holder's edge giving it
/// below admin at their `ts`, but finalizes; under `Candidates::Explicit` no self-removal and none
/// applied as an invite grant where trusted), not trusted and not dropped by a trusted write's
/// seeds, whose trust changes the reading (what applies, what is valid, the roles).
/// spec/permissions.md §5.1 asks instead that the walk not apply it, that it apply once trusted and
/// lower its edge (finding 21); a removal that applies but whose reach-back the walk cannot undo
/// (its drops of a lowering that dropped in turn, or of a grant a lowering applied under) changes
/// the reading once trusted and is shown only by this rule (finding 16). A grant at admin is never
/// one: trusted, its seeds drop its holder's earlier writes, so an honest re-grant would be shown.
pub fn disputes(w: &World, rules: &Rules, v: &View) -> Vec<Id> {
    disputes_by(w, rules, v, |t, rd| t.applied != rd.applied || t.valid != rd.valid || t.roles != rd.roles)
}

/// `disputes`, with what a candidate's trust must change given: `differs(trusting it, the
/// reading)` (osis-perm's walk judges edge-class parts first: what applies and the roles).
pub fn disputes_by(w: &World, rules: &Rules, v: &View, differs: impl Fn(&Reading, &Reading) -> bool) -> Vec<Id> {
    let rd = judge(w, rules, v);
    let explicit = rules.candidates == Candidates::Explicit;
    let mut out = vec![];
    for &r in &v.held {
        let Kind::Edge { holder, .. } = &w.commits[r].kind else { continue };
        if *holder == w.commits[r].signer || rules.lowering(w, r).is_none() || (explicit && w.leave(r)) || v.trust.contains(&r) || rd.dropper.get(&r).is_some_and(|d| v.trust.contains(d)) {
            continue;
        }
        let t = judge(w, rules, &v.clone().trusting_also(r));
        if explicit && t.invited.contains(&r) {
            continue;
        }
        if differs(&t, &rd) {
            out.push(r);
        }
    }
    out
}

/// The edges whose edge writes are evidence of commit `i`: its path's, and the remaining admin
/// edge it names.
fn evidence_edges(w: &World, i: Id) -> Vec<Edge> {
    let mut e = w.hops(i).to_vec();
    if let Kind::Edge { relies: Some(n), .. } = &w.commits[i].kind {
        e.push((*n, w.commits[i].on));
    }
    e
}

/// The evidence closure of `unit` over `avail` (notes/write-path-design.md §2): the commits in
/// `unit`, the other parts of a held commit on the same thing (a part on another thing is that
/// thing's unit's, with its own path: notes/path-form.md), every available edge write on an edge
/// of a held part's path or on the remaining admin edge a held lowering names, every available
/// vouch against a held removal on a thing a held part is on (a vouch on N counts parts on N
/// alone, so one on a thing the set holds nothing on is read by no verdict on it).
pub fn evidence(w: &World, unit: &Set, avail: &Set) -> Set {
    let mut s = unit.clone();
    loop {
        let edges: BTreeSet<Edge> = s.iter().flat_map(|&i| evidence_edges(w, i)).collect();
        let cids: BTreeSet<(Id, Thing)> = s.iter().map(|&i| (w.cid(i), w.commits[i].on)).collect();
        let more: Vec<Id> = avail
            .iter()
            .copied()
            .filter(|i| !s.contains(i))
            .filter(|&i| cids.contains(&(w.cid(i), w.commits[i].on)) || match &w.commits[i].kind {
                Kind::Edge { .. } => w.sets(i).is_some_and(|e| edges.contains(&e)),
                // a vouch on N counts only parts on N: read only where the set holds something on N
                Kind::Vouch { removal, .. } => s.contains(removal) && s.iter().any(|&j| w.commits[j].on == w.commits[i].on),
                _ => false,
            })
            .collect();
        if more.is_empty() {
            return s;
        }
        s.extend(more);
    }
}

// ---- The keys layer: A's epochs under a standing dispute (spec/crypto.md §4) ----

/// What one node's reading gives the keys layer: A's admins and the departures it knows.
#[derive(Clone, Debug, PartialEq)]
pub struct Side {
    pub node: Thing,
    pub admins: Things,
    pub departures: Set,
}

impl Side {
    pub fn of(w: &World, rd: &Reading, node: Thing, a: Thing) -> Side {
        Side {
            node,
            admins: rd.roles.iter().filter(|(e, r)| e.1 == a && **r == Role::Admin).map(|(e, _)| e.0).collect(),
            departures: rd.lowered.iter().copied().filter(|&i| w.commits[i].on == a).collect(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Withdraw {
    /// spec/crypto.md §4 as written: a valid rotation is current whatever it covers; the
    /// knowing re-key answers a current epoch not covering a known departure; a node withdraws
    /// an epoch not current whose maker may not rotate.
    AsWritten,
    /// The fix: an epoch covering a departure the node's walk does not apply is the other
    /// side's: it is read, never current, supersedes nothing and is not answered.
    SideOnly,
}

#[derive(Clone, Debug)]
pub struct Epoch {
    pub maker: Thing,
    pub covers: Set,
    pub boxes: Things,
    pub supersedes: BTreeSet<usize>,
}

/// Every node holds every epoch; each pass, each node in turn rotates A when the rule says so.
/// Returns the epochs (0 the first, valid everywhere) and the rotations made per pass.
pub fn rotations(passes: usize, rule: Withdraw, sides: impl Fn(usize) -> Vec<Side>) -> (Vec<Epoch>, Vec<usize>) {
    let mut eps = vec![Epoch { maker: 0, covers: Set::new(), boxes: Things::new(), supersedes: BTreeSet::new() }];
    let mut per = vec![];
    for pass in 0..passes {
        let mut made = 0;
        for s in sides(pass) {
            let cur = current(&eps, &s, rule);
            let counted = |i: usize| counts(&eps, i, &s, rule);
            let superseded = |i: usize| (0..eps.len()).any(|f| counted(f) && eps[f].supersedes.contains(&i));
            let withdrawn: Vec<usize> = (1..eps.len()).filter(|&i| !counted(i) && !superseded(i) && (eps[i].maker == s.node || !s.admins.contains(&eps[i].maker))).collect();
            if !s.admins.contains(&s.node) || (!cur.is_empty() && cur.iter().all(|&i| eps[i].covers.is_superset(&s.departures)) && withdrawn.is_empty()) {
                continue;
            }
            let supersedes = cur.into_iter().chain(withdrawn).collect();
            eps.push(Epoch { maker: s.node, covers: s.departures.clone(), boxes: s.admins.clone(), supersedes });
            made += 1;
        }
        per.push(made);
    }
    (eps, per)
}

fn counts(eps: &[Epoch], i: usize, s: &Side, rule: Withdraw) -> bool {
    i == 0 || (s.admins.contains(&eps[i].maker) && (rule == Withdraw::AsWritten || eps[i].covers.is_subset(&s.departures)))
}

/// The epochs current at a node: counting, superseded by no counting epoch.
pub fn current(eps: &[Epoch], s: &Side, rule: Withdraw) -> Vec<usize> {
    (0..eps.len()).filter(|&i| counts(eps, i, s, rule) && !(0..eps.len()).any(|f| counts(eps, f, s, rule) && eps[f].supersedes.contains(&i))).collect()
}

mod purge;
mod story;
pub use purge::*;
pub use story::*;

#[cfg(test)]
mod tests;
