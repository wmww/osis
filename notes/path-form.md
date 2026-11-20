# Path form
> Summary: Proposal (not built, not in spec; the coordinator puts the open points to Tess): how a commit states the path each thing it writes is judged along. One path in the clear where one serves every thing (almost every commit); else the split form: one purge author in the clear and each thing's path sealed in the header under that thing's roles secret. Who reads a path, per consumer (no node that cannot read a thing ever needs its path); purge per thing; one purge author per commit (`act_as`, a1-spec Open 16); the engine's search; what replaces the hashed form, in steps; bytes; the model check (roles-model `paths`: `World::split`); what needs Tess.

**Principle: a thing's path is header data, readable exactly by the nodes that judge that thing's parts.** Every node that holds a header and judges a thing reads the thing's path from the header, with or without the thing's section. Where one path serves every thing written, it is stated once in the clear (every header reader judges, or may learn, the same chain). Where things need different paths, each thing's path is sealed to the nodes that judge that thing, and nothing else of it is in the clear. A write is never refused or split for its paths: a commit may span things its signer reaches through different actors.

Status: *proposed*. Built today: notes/a1-spec/README.md (step 2), spec/wire.md §4 (one path in the clear, else the hashed form: a salted hash per thing in the header, each thing's path in its sections).

## Who reads a path, and who never needs one
A thing T's path is read by every node that judges T's parts, for every commit writing T it holds, section or not: what a part waits on (`apply/waits.rs`), the validity of every aspect row of T (`apply/atomic.rs` `part_valid`; a part not held, joining late, undone, replaced; held-model's `held_set_decides`), a purge request on T, the chain certificates of T's parts, addenda and vouches on T, a cover's facts (these read only the purge author). The nodes that judge T's parts are T's holders: a node holding T whole reads it (spec/commits.md §4 Outside the node closure: content on a thing the node does not read applies nothing; other parts wait until it holds it whole), and every holder of T opens T's role parts with T's **roles secret** (spec/crypto.md §4 Roles secrets: a holder of a floor included). So T's roles secret is the key that reaches exactly T's judges; the path, a fact of T's roster, is what roles secrets already open.

Two kinds of parts are judged by nodes that do not hold their thing, so their commits state one path in the clear:
- role commits (kind 1, 3): their parts travel as chain certificates and role entries to nodes reading only things the edge leads to (spec/permissions.md §4, spec/sync-judgement.md §2); a role commit writes one target (spec/commits.md §2), so one path serves it;
- a request destroying a thing (`[tid, created.0]`): its header goes as a certificate to nodes needing the destroyed thing (spec/commits.md §5 Destruction).

Stores and nodes keeping a sync ID unread open no blob, so read no header and no path: they act on delete commitments alone.

## One path
- **Path**: `[i, A1, …, Ak]`, k ≥ 0: the purge-author index then the listed things. Its **end** is Ak (the signer S where k = 0).
- **Members** for a thing T written along it: [S, A1, …, Ak, T]; where T is the end, [S, A1, …, Ak]. Hops, descent, the last edge, a self-removal ending at its holder, "a thing named twice is invalid": as notes/a1-spec/permissions.md §1.
- So one path writes its end, the things the end holds a direct grant on, and the things descending from the end by record edges (one hop past the end). For every thing written the path is that thing's own holder chain, so no reader learns a chain that is not its own thing's (spec/requirements.md, Confidentiality between readers).
- A commit states one path wherever one gives every thing written the role its parts need: a writer rule (a decoder cannot check it). Of about 6,350 commits writing two things or more in the default tests, one needs two paths (`validity::a_write_states_the_holders_it_goes_through_spec_wire_4`, built by hand); every creation under a granted parent is one path (`[D]`: D the end, the new thing one record edge past it).

## Several paths: the split form
Wire text (draft for spec/wire.md §4; notes/a1-spec/wire.md holds it in place):
```
Paths     := Path | Split
Split     := [Opt(tid), [bytes+]]   ; the purge author (absent: the signer), then one sealed path per thing written
PathKey   := [index, bytes]         ; in a copy: a thing's index among the things written, its path key
```
- `Split` is stated where no one path serves every thing; one entry per distinct tid `aspects` names, in that order, n ≥ 2 (bad input otherwise, checked once `aspects` resolves).
- Entry of thing T: XChaCha20-Poly1305 of the canonical `[tid*]` (T's listed things A1..Ak, read with T's members as above; no index), nonce 24 zero bytes, empty AD, under T's **path key** `kdf("path", roles secret, blind ‖ T's tid)`: the roles secret (spec/crypto.md §4, `kdf("roles", s)`) of T's read secret s (own or derived, spec/crypto.md §3) at the epoch T's section is sealed under (the writer's newest current read epoch of T), `blind` the header's field 10. One plaintext per key: the blind is fresh per commit and the tid distinct per entry. 17 + 16k bytes.
- A reader of T tries the roles secrets it holds of T, own and derived up T's record chain, newest first, as for a section. The decrypted list obeys `Path`'s rules (k ≤ MAX_PATH_THINGS, no tid twice, none equal to `signer`), else T's parts hold nothing (as bytes that do not match the header's delta hash: invalid at every reader of T alike).
- **Purge author**: one per commit, in either form: a Path's index, a Split's `Opt(tid)` (not `signer`). It is a member of every thing's members: a reader of T judges that for T; where it is not, T's parts are invalid (Open 16 below). Being on every thing's path, it shows each thing's readers nothing beyond their own thing's chain; the header's one level-2 key (spec/crypto.md §7: the purge author's) shows them no more.
- Bad input: `Split` on a role commit (kind 1, 3), beside a purge item on `created.0`, with fewer than two things, an entry count other than the things written, an entry shorter than 17 bytes or longer than a `Path` of MAX_PATH_THINGS sealed.
- **Copies**: a copy's section (spec/sync-judgement.md §1, under its blob key) is `[[Part*], [PathKey*]]`: for each thing whose parts it holds, where the header is `Split`, that thing's path key, so whoever opens a copy of T's parts opens T's path (a node reading T only by copies, as for a destroyed mint admin's dependents, judges T's parts). A thing's own section is `[Part*]`.
- Signed: entries and author sit in the header, so the commit ID covers them; an entry opens only under its own thing's key for this commit (key from T's secret, T's tid and this header's blind), so it cannot be moved to another thing or commit, and no path can be swapped under a signature.

What a reader of A learns of another thing B of a split commit: that B is written (its tid, as in any commit), that the commit is split (no one path served both), and B's entry size, so the number of things B's path lists (Open for Tess, below). Nothing names a holder on B's chain.

### Per consumer: does a node that cannot read B ever need B's path
"Cannot read B": holds the header but no roles secret of B at the epoch B's entry is sealed under.

| consumer | who needs B's path | a non-reader of B |
|---|---|---|
| pending, waits (`pend_needs`) | per part: B's part waits on the records its own path lists and on its edges (spec/commits.md §4 Unjudgeable reads a held part's own path); the commit waits only while every held part does | never: B's content applies nothing there and other parts on B wait as outside the node closure, reading no path. A holder of B lacking that epoch (its box not yet in) waits on B's part alone, examined again when the held role inputs move |
| validity of B's rows, held or not | B's holders | never: it judges no part of B |
| purge request on B | judged along B's own path (the commit has a delta on every thing a request names, spec/commits.md §5), applied by the nodes holding B's deltas: B's readers | never (it holds no content of B; stores delete by keys). A destroying request, judged by non-holders, states one clear path |
| could hold the right (spec/commits.md §4 draft) | per thing, along that thing's path, at nodes holding it whole | never |
| level-2 delete keys | one per commit: the purge author's, in the clear | never needs a path: keys follow the clear purge author (`retention/names.rs`, `freed.rs`, the level-2 row of `sync/mod.rs`) |
| cover facts (`snapshot::header_fact`) | the purge author and class, clear | never needs a path |
| chain certificates, A2 evidence | S's body carries the chain certificates of its parts' things, each along its own path (spec/permissions.md §4 draft): the evidence of S is the closure over the paths of the parts of its bodies, computed by S's readers, who open each such thing's path (its secrets derive from S's actor or come boxed to it, spec/sync-judgement.md §1; copies carry path keys) | never: B's chain goes only under sync IDs whose bodies hold B's parts, so A's readers never receive B's certificates |
| frontier of a lowering of h | the remover lists every received commit resting on h | lists every received commit with an entry it cannot open: a list naming a commit none of whose parts rests on h changes nothing (spec/permissions.md §5.1: lists are read only for parts resting on h), and one whose part on B does is one it received |
| addenda, vouches on N | their writer, a reader of N | never |
| listing rows, `HeldCommit.acting`, stamps (`Stamp.actor`), fired signals, `replaces` honoured | the purge author, clear, one per commit | never needs a path |
| undo | the undone commit's parts per thing; an undo spanning places is itself split | a part it cannot judge is not held: the commit cannot be undone there (spec/commits.md §7) |

So the "unknown" state is a header holder without B's roles secret at that epoch: either not a holder of B (it judges nothing of B anyway) or a holder whose box has not arrived (B's part alone waits, as for any role input). Two nodes holding the same data, secrets included, judge alike.

A commit is half valid where a removal cuts one thing's path and not another's: each part is judged on its own and an invalid one is un-merged alone (spec/commits.md §4: "Each delta is judged on its own ... the commit's other deltas stand"; notes/a1-spec/commits.md §2: a receiver judges a commit part by part), as for any multi-thing commit today.

## Whom a write is by (`act_as`, a1-spec Open 16)
- One purge author per commit (above), so at most one level-2 key in `keys` (the Interim check in `validate.rs` is the rule) and one actor per commit for every consumer reading "the actor".
- The purge author is a member of every thing's path: S, a listed thing, or the thing written (T is always a member of its own members; one path names it by listing it last, index k). `act_as(X)` asks the engine for paths through X for every thing.
- **X not on some thing's path** (X holds no role leading to it): a write error (`Permission`), proposed. Main accepts it where the signer may write X (the Acting check), which the thing's readers check only through X's roster, one giving no role on the thing (spec/requirements.md, Confidentiality between readers) and absent from evidence along stated paths (A2). Removed capability: labelling a write as by an identity whose authority does not reach what it writes, including acting as X in a write that also writes things X does not reach. Granting X a role gives the label with a checked path. No caller in chat, app, kit or CLI uses `act_as`. **For Tess** (below).
- **X the thing written** (T on T): allowed. A commit acting as room D that writes D and a thing under D is one path `[D]`, index 1.
- A request by author holds the right over a delta iff the author is among the request's members for that thing and the request is valid (notes/write-path-design.md §1, with "members" for "path").

## The engine's search
- First ONE path serving every thing (each at the role its aspects need), through X where acting for X: one search over the things together, not per-thing searches compared afterwards (per-thing searches can pick different routes where one serves both).
- None: the split form, each thing its own path, the shortest by edges from the signer (through X: to X, X, then X's path to the thing), ties by the backward breadth-first search's first meeting (`osis_perm::graph::View::ways_to`, memoized per (thing, role)). Both are functions of the held edges.
- No grouping of things into "as few paths as possible" is attempted: each thing has its own entry under its own key either way, so grouping saves nothing.
- osis-perm `paths` takes each part with its own `on` and `path` (`paths::Part`): the adapter hands each part its thing's path (less a trailing `on`); the walk is unchanged. Content parts reach it at 3b by the same input.

## What replaces the hashed form
Map: origin/windlass-one-path (208b825d6, not for building) touches every site in core/commit; `Path::to` there is the one-hop reading in code.
| hashed form | replaced by |
|---|---|
| `Paths::Hashed`, header hashes, `kdf("path", salt, Path)` | `Paths::Split { author, entries }`; `kdf("path", roles secret, blind ‖ tid)` |
| `Salted` in every section of a thing and copy; `Contents := [Opt(Salted), [Part*]]`; `CommitBlob::salted`, `salted_of`, `check_paths`; the stored and fire-payload `[[i, Salted]+]` | nothing in a thing's section (`[Part*]`, 2 B smaller); a copy's `[PathKey*]`; a thing's path opened from the header with held secrets, cached in the commit record as header data |
| the per-thing section split in `seal_commit` and copies (the issue's first class) | sections as in the clear form: no path rides in them |
| `Acting::Each`, `View::acting_on(t)` | one purge author per commit, clear: `View::acting` |
| late-learned acting (`atomic::join_late`), `RecordHead::acting` | nothing: the author is clear; a thing's path is known once its secret is held, its part examined again then |
| per-part hashed wait in `apply::examine` | the per-part wait on a part's own path (kept), plus "entry not opened yet": waits on the held role inputs |
| `undo::undone_parts`' unknown-path case | a part its node cannot judge is not held |
| `Header::validate`'s hashed-beside-purge | `Split` beside a destroying request, or on a role commit, is bad input |
| hooks `Core::hashed_through`, `Core::forced_paths`; the four `validity::*hashed*` tests; the `commit_header` corpus' hashed entries | tests writing across two places for real; a wip-only forcing of the split form on every multi-thing commit to run the suites once; split entries in the corpus; vectors regenerated |
| the Interim's "where paths differ, one path for all" in `stated_path` | the search above |

The issue's second class (a part not held, its path unknown) goes because the path is in the header: a node holding the thing holds the key.

## Steps
Each leaves main working; spec and code together (notes/a1-spec/README.md, Order of the code briefs).
1. **The form** (step 2, the rest, first brief): spec/wire.md §4 (`Paths`, `Split`, entries, path key, the copy's path keys, `Contents := [Part*]`, the copy's section, bad input), §12; spec/crypto.md §5 a Path entry bullet; core/commit (`Paths::Split`, builder `thing_paths` with each thing's roles secret, `author`; opening an entry); engine sealing, opening, `acting` one tid, the per-part "entry not opened" wait; every row of the table above but the last; the engine still writes one path (Interim), a test hook writes the split form.
2. **The engine writes it** (second brief): `stated_path` as The engine's search; `act_as(X)` with no path through X for some thing fails `Permission`; the frontier lists commits with entries it cannot open; S's bodies carry the chain certificates of their parts' things only (spec/permissions.md §4, spec/sync-judgement.md §2 certificate blobs: "to each thing of the body under S"); the hooks go; issues/hashed-paths-forced-suite-gaps.md closes once the suites pass with the form forced (wip) and for real.
3. **Step 3** (the walk by path) unchanged: each part with its own path; role commits state real paths (always one).
4. **Step 4**: one purge author per commit is the encoding already; a purge request is judged per thing it names along that thing's path; the author right reads members.

## Bytes
Header fields `signer`, `path`, `remains` (a tid 16 B encoded); accounts as today.
| commit | bytes |
|---|---|
| own things (one path `[0]`) | 19 |
| creation under a granted parent (`[0, D]`) | 35 (hashed form: 86 in the header, 56 in its two sections) |
| at or under the last of k holders | 19 + 16k |
| two paths: an own thing and a thing under D | 73: `Split` 56 (3 + an entry of `[]` 18 + of `[D]` 35) |
| n things, thing i's path listing k_i | 20 + Σ e(k_i), e(0) = 18, e(k) = 19 + 16k for k ≥ 1 (n ≥ 24: +1); +16 for a purge author other than the signer |
A copy of a split commit adds about 36 B per thing whose parts it holds (its path key). Every section is 2 B smaller than built (no `Contents` head).

## The model
roles-model `paths` judges each part by (signer, its own path, `on`), so a split commit changes no reading: `World::split` writes one commit (grouped, so a list naming it names every part) with each thing's own path and one purge author. Hand world `a_commit_spanning_two_paths_is_judged_per_thing_as_one_commit_per_thing`: X writes T1 along [A] and A2 along its own grant, as one commit and as two at the same key; every reading (valid, purged, applied, roles) agrees across: no removal, H's removal of X from A (T1's part falls, A2's stands), K's removal from A2 (the reverse), a removal listing the commit, X's purge by author on T1 (T1's part alone). Order within a commit (a1-spec Open 14) reads only edge writes, which a split commit has none of (role commits are one path). `evidence` takes a held commit's other parts only on the same thing: a unit holding T1's part needs no edge of A2's path (asserted in the same test). Every grouped commit the generators make is on one thing (`World::commit`), so no generated world reads differently; default tests pass, the gate's paths properties are not re-run. Owed if Open 16 is taken as proposed: `Rules::author_thing` on in `fixed`, with deltas by their own thing in the `tiny` purge worlds.

## Rejected
- **Refuse or split a multi-path write**: rejected by the owner: a commit may span things reached through different actors.
- **The hashed form** (each path in its thing's sections): a path is header data; in a section it is missing exactly where the consumers above read it (a second "unknown here" case per consumer, `Salted` in every section, copies split per thing, paths learned late and kept past their parts).
- **A clear primary path for the things it serves, sealed paths for the rest**: the primary's chain is shown to the other things' readers (rosters giving no role on them); it is safe only as the empty path, a second form saving about 18 B a thing on rare commits.
- **Every path sealed, one-path commits too**: about 18 B on every thing of every commit, and every header reader of a one-path commit needs a secret for what is shown to all alike.
- **Paths in the clear with members blinded per thing**: a blinded member resolves only by testing candidates a reader already knows, but a pending part needs the tid of a record it has not seen to fetch it; a per-commit blind keyed by B's secret is sealing at the same cost.
- **A path entry under the read secret**: a holder of a floor (roles secrets alone for older epochs) judges B's parts but could not open it.
- **A purge author per thing**: a level-2 key per author, shown in the clear to every thing's readers, names a holder on another thing's chain; one author per write is what `act_as` offers.

## For Tess
1. Proposed property (spec/requirements.md, Commits or Confidentiality between readers): "A write may span things reached through different actors; it is one commit."
2. Open 16, the capability: may a write's author (`act_as(X)`) be a thing whose authority does not reach every thing the write writes? Proposed no (error). Lost: labelling a write as by an identity with no role on what it writes (no caller does); granting X a role gives the same with a checked path.
3. Path length: in a split commit a reader of A sees the size of B's entry, so how many things B's path lists (no identity). (a) Accept, as section sizes are (*taken*). (b) Pad every entry to MAX_PATH_THINGS: closes it, about 1 KiB a thing on split commits (a split commit can write thousands of things). (c) Pad entries to the commit's longest: shows the longest only. "Learn nothing of rosters that give no role on it" reads (a) as a size leak of a roster fact; (a) needs her word if the requirement is read strictly.
