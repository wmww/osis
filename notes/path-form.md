# Path form
> Summary: Proposal (not built, not in spec; the coordinator puts the open points to Tess): how a commit states the path each thing it writes is judged along. One path in the clear where the things' own paths are one (almost every commit); else the split form: one purge author in the clear and each thing's path sealed in the header under its independent's read roles secret, its key also in every encryption of its parts. Who reads a path, per consumer (no node that cannot read a thing ever needs its path); purge per thing; one purge author per commit (`act_as`, a1-spec Open 16); the engine's choice per thing; what replaces the hashed form, in steps; bytes; the model check (roles-model `paths`: `World::split`); what needs Tess.

**Principle: a thing's path is header data, readable exactly by the nodes that judge that thing's parts.** Every node that holds a header and judges a thing reads the thing's path from the header, with or without the thing's section. Where the things' paths are one, it is stated once in the clear. Where they differ, each thing's path is sealed to the nodes that judge that thing, and nothing else of it is in the clear. A write is never refused or split for its paths: a commit may span things its signer reaches through different actors.

Status: *proposed*, reviewed against spec and code (the holes found are closed below). Built today: notes/a1-spec/README.md (step 2), spec/wire.md §4 (one path in the clear, else the hashed form: a salted hash per thing in the header, each thing's path in its sections).

## Who reads a path, and who never needs one
A thing T's path is read by every node that judges T's parts, for every commit writing T it holds, section or not: what a part waits on (`apply/waits.rs`), the validity of every aspect row of T (`apply/atomic.rs` `part_valid`; a part not held, joining late, undone, replaced; held-model's `held_set_decides`), a purge request on T (dropping held deltas and the copies of named writes in held snapshots, spec/commits.md §5 Without the header), the chain certificates of T's parts, addenda and vouches on T, a cover's facts (these read only the purge author). The nodes that judge T's parts are T's holders: a node holding T whole reads it (spec/commits.md §4 Outside the node closure: content on a thing the node does not read applies nothing; other parts wait until it holds it whole), and every holder of T holds the read roles secrets of T's independent (spec/crypto.md §3, §4 Roles secrets: derived, boxed, or, below a floor, from history entries).

Node classes and the key (`kdf("path", roles secret of T's independent at the epoch T's section is sealed under, blind ‖ tid)`):
| class | judges T's parts | opens T's entry |
|---|---|---|
| reader, writer, admin of T or of a holder of T (boxes to the holder) | yes | yes |
| reader of a sync ID whose unit holds T (T derives from its actor, or its actor reads T's independent by grants with key access) | yes | yes |
| holder of a floor on T's independent, for epochs below it | only role parts (clear path) and lasting headers' requests on copies it holds | yes: history entries carry earlier roles secrets of the independent (a dependent thing's derived roles secret it could not form: why the key is the independent's) |
| holder granted without history, commits below its cut | none: no content header reaches it (spec/crypto.md §5 floors) but lasting headers, as above | yes, as above (old roster facts it may read anyway) |
| holder lacking the entry's epoch (box not in, left out, rotator not carrying it) | only once it holds a part: then from that encryption's key | by the key in any encryption of T's parts it opens (a re-encryption under a later epoch included); with none, the part waits until a History add brings the epoch |
| removed reader | no (it drops T, spec/permissions.md §3 Lost access) | for epochs it held: what it read then |
| reader of another thing B of the commit | no | no |
| node holding T's secrets but not T (outside its node closure, a ticket's word) | no (nothing applies there) | perhaps; it may read T's content anyway |
| node reaching T only by a keyless grant | no (no secret, no read) | no |
| node needing a destroyed T (dependents' holders) | the destroying request's right, the frozen roster | by the path key in the request's header-only copy (below) |
| store, node keeping a sync ID unread | nothing: no header, no path (wraps under read secrets) | no |

Two kinds of parts are judged by nodes that do not hold their thing:
- role parts: they travel as chain certificates and role entries to nodes reading only things the edge leads to (spec/permissions.md §4, spec/sync-judgement.md §2). A role commit states one clear `Path` (`Split` there is bad input): a writer rule, since spec/commits.md §2 lets a rotation, re-seal, `keys.0` or `sync.0` write cover many things. The engine writes one thing per role commit (`rotation::rotate_now`, `own_secrets_rot`: the thing and its own sync ID), and a writer making a role commit over things one path does not serve makes one per path. A grant, removal, redemption (both edges on K) and vouch write one target.
- a request destroying a thing (`[tid, created.0]`): its header goes as a header-only certificate copy to nodes needing the destroyed thing (spec/commits.md §5 Destruction). In a split commit that copy carries the destroyed thing's path key in one section under its blob key; those nodes hold the thing's frozen roster anyway.

Stores and nodes keeping a sync ID unread open no blob, so read no header and no path: they act on delete commitments alone.

## One path
- **Path**: `[i, A1, …, Ak]`, k ≥ 0: the purge-author index then the listed things. Its **end** is Ak (the signer S where k = 0).
- **Members** for a thing T written along it: [S, A1, …, Ak, T]; where T is the end, [S, A1, …, Ak]. Hops, descent, the last edge, a self-removal ending at its holder, "a thing named twice is invalid": as notes/a1-spec/permissions.md §1.
- So one path writes its end, the things the end holds a direct grant on, and the things descending from the end by record edges (one hop past the end).
- What a reader of thing B learns of the others: their chain up to the end is B's own (or a prefix of it); for a sibling T one hop past the end, that the end holds a role on T (T's last edge, a fact of T's roster: For Tess 3).
- The clear form is used exactly where each thing's own path (The engine's choice) is read off one `Path`: a writer rule (a decoder cannot check it). Of about 6,350 commits writing two things or more in the default tests, one needs two paths (`validity::a_write_states_the_holders_it_goes_through_spec_wire_4`, built by hand); every creation under a granted parent is one path (`[D]`: D the end, the new thing one record edge past it).

## Several paths: the split form
Wire text (draft for spec/wire.md §4; notes/a1-spec/wire.md holds it in place):
```
Paths     := Path | Split
Split     := [Opt(tid), [bytes+]]   ; the purge author (absent: the signer), then one sealed path per thing written
PathKey   := [index, bytes]         ; a thing's index among the things written, its path key
Contents  := [Part*]                ; where path is a Split: [[Part*], [PathKey*]]
```
- `Split` is stated where the things' own paths are not one `Path`; one entry per distinct tid `aspects` names, in that order, n ≥ 2 (bad input otherwise, checked once `aspects` resolves).
- Entry of thing T: XChaCha20-Poly1305 of the canonical `[tid*]` (T's listed things A1..Ak, read with T's members as above; no index), nonce 24 zero bytes, empty AD, under T's **path key** `kdf("path", roles secret, blind ‖ T's tid)`: the read roles secret (spec/crypto.md §4, `kdf("roles", s)`) of T's independent (T itself where independent; spec/crypto.md §3) at the epoch the writer seals T's section under (its newest current read epoch of T, for a dependent T the independent's epoch it derives from), `blind` the header's field 10. 17 + 16k bytes.
- **Every encryption of T's parts carries T's path key**: each section of T (its role section has none: role commits are never split) and each copy holding T's parts. Sections are re-encrypted under later epochs (a fresh encryption, a retag, a deposit), but the header never is, so a reader holding only the later epoch opens the path from the section it reads. A copy is the same rule (a node reading T only by copies, as for a destroyed mint admin's dependents, judges T's parts).
- A reader of T tries the key in each encryption of T's parts it opened, then the read roles secrets it holds of T and up T's record chain, newest first. The decrypted list obeys `Path`'s rules (k ≤ MAX_PATH_THINGS, no tid twice, none equal to `signer`), else T's parts hold nothing (as bytes that do not match the header's delta hash: invalid at every reader of T alike). A key in an encryption that does not open its entry makes that encryption hold nothing.
- **Purge author**: one per commit, in either form: a Path's index, a Split's `Opt(tid)` (not `signer`). It is a member of every thing's members: a reader of T judges that for T; where it is not, T's parts are invalid (Open 16 below). Being on every thing's path, it shows each thing's readers only their own thing's chain; the header's one level-2 key (spec/crypto.md §7: the purge author's) shows them no more.
- Bad input: `Split` on a role commit (kind 1, 3), with fewer than two things, an entry count other than the things written, an entry shorter than 17 bytes or longer than a `Path` of MAX_PATH_THINGS sealed.
- Signed: entries and author sit in the header, so the commit ID covers them; an entry opens only under its own thing's key for this header (T's secret, T's tid, this header's blind), so it cannot be moved to another thing or commit under a signature.

What a reader of A learns of another thing B of a split commit: that B is written (its tid, as in any commit), that the commit is split (B's own path is not read off A's), and B's entry size, so the number of things B's path lists (For Tess 3). Nothing names a holder on B's chain.

### Crypto
- One plaintext per key: `blind` is 16 random bytes per commit, the tid distinct per entry, the epoch fixed by the header; the header is never encrypted again (rotations and re-wraps re-encrypt sections and wraps, never the header), so an honest writer never reuses a key.
- A writer reusing a blind across its own commits on T at one epoch reuses the keystream and the Poly1305 key there: a reader of the commits' other things sees the XOR of the two paths and could forge an entry under that key. Only the writer can do that, and it gains nothing it could not get by publishing its paths; a forged entry sits in no header anyone signed. The key does not bind the signer: an entry copied into another signer's header opens to the same list, judged with that signer's members, which gives it nothing its own path could not.
- Empty AD: the key binds thing, commit and epoch; a swapped entry fails to open.

### Per consumer: does a node that cannot read B ever need B's path
"Cannot read B": holds the header but neither a roles secret of B's independent at the entry's epoch nor an encryption of B's parts.

| consumer | who needs B's path | a non-reader of B |
|---|---|---|
| pending, waits (`pend_needs`) | per part: B's part waits on the records its own path lists and on its edges (spec/commits.md §4 Unjudgeable reads a held part's own path); the commit waits only while every held part does (`apply::examine` already waits per part) | never: B's content applies nothing there and other parts on B wait as outside the node closure, reading no path. A holder of B lacking the epoch and every encryption of B's parts waits on B's part alone, examined again when the held role inputs or encryptions move |
| validity of B's rows, held or not | B's holders | never: it judges no part of B |
| must-hold, judged invalid, the author's chain in a required set | S's readers, over S's body: the parts of things S's actor may read (spec/sync-judgement.md §1, §2), whose entries they open | never: it judges blobs on the sections it opened (Per blob) |
| purge request on B | judged along B's own path (the commit has a delta on every thing a request names, spec/commits.md §5 Purge), applied by B's holders, also to copies of named writes in their snapshots | never (it holds no content of B; stores delete by keys). A destroying request's judges get B's path key in its header-only copy |
| could hold the right (spec/commits.md §4 draft) | per thing, along that thing's path, at nodes holding it whole | never |
| level-2 delete keys | one per commit: the purge author's, in the clear | never needs a path: keys follow the clear purge author (`retention/names.rs`, `freed.rs`, the level-2 row of `sync/mod.rs`) |
| cover facts (`snapshot::header_fact`) | the purge author and class, clear | never needs a path |
| chain certificates, A2 evidence | S's body carries the chain certificates of its parts' things, each along its own path (spec/permissions.md §4 draft): the evidence of S is the closure over the paths of the parts of its bodies, computed by S's readers, who open each such entry (a copy carries the keys); the path's members name the edges outside the unit to fetch evidence for | never: B's chain goes only under sync IDs whose bodies hold B's parts |
| frontier of a lowering of h | the remover lists every received commit resting on h | lists every received commit with an entry it cannot open: The list (permissions.md §5.1) lists every received commit resting on h anyway, a list is read only for parts resting on h, and a split commit is no role commit, so it never takes R's authority (the one-by-one fallback reads role commits only) |
| addenda, vouches on N | their writer, a reader of N | never |
| listing rows, `HeldCommit.acting`, stamps (`Stamp.actor`), fired signals, `replaces` honoured | the purge author, clear, one per commit | never needs a path |
| undo | the undone commit's parts per thing; an undo spanning places is itself split | a part it cannot judge is not held: the commit cannot be undone there (spec/commits.md §7) |

Two nodes holding the same data, secrets and encryptions included, judge alike. A commit is half valid where a removal cuts one thing's path and not another's: each part is judged on its own (spec/commits.md §4: "Each delta is judged on its own ... the commit's other deltas stand").

## Whom a write is by (`act_as`, a1-spec Open 16)
- One purge author per commit (above), so at most one level-2 key in `keys` (the Interim check in `validate.rs` is the rule) and one actor per commit for every consumer reading "the actor".
- The purge author is a member of every thing's path: S, a listed thing, or the thing written (T is always a member of its own members; one path names it by listing it last, index k). `act_as(X)` asks the engine for each thing's path through X.
- **X not on some thing's path** (X holds no role leading to it): a write error (`Permission`), proposed. Main accepts it where the signer may write X (the Acting check, `write::check_acts`, `validity::acts_for`), each part valid by the signer's own role on its thing by any route. The thing's readers could check that only through X's roster, one giving no role on the thing (spec/requirements.md, Confidentiality between readers), absent from evidence along stated paths (A2). **For Tess** (below).
- **X the thing written** (T on T): allowed. A commit acting as room D that writes D and a thing under D is one path `[D]`, index 1.
- A request by author holds the right over a delta iff the author is among the request's members for that thing and the request is valid (notes/write-path-design.md §1, with "members" for "path").

## The engine's choice
- Each thing gets its own path: the shortest by edges from the signer giving the role its aspects need (through X where acting for X: to X, X, then X's path to the thing), ties first toward routes that make every thing's path one `Path`, then by the backward breadth-first search's first meeting (`osis_perm::graph::View::ways_to`, memoized per (thing, role)). A function of the held edges.
- The clear form where those paths are read off one `Path` (each thing the end or one hop past it), else `Split`. Never a longer route for one thing so that one path serves all: a part rests on its stated path's edges alone (cut, listed, re-granted by them), so routing T through O where S holds a direct grant on T lets a removal of S from O take a write S could still make directly, and re-grant then reads only the route through O. This is main's Interim order too (per thing, then compared).
- No grouping of things into "as few paths as possible": each thing has its own entry under its own key either way, so grouping saves nothing.
- osis-perm `paths` takes each part with its own `on` and `path` (`paths::Part`): the adapter hands each part its thing's path (less a trailing `on`); the walk is unchanged. Content parts reach it at 3b by the same input.

## What replaces the hashed form
Map: origin/windlass-one-path (208b825d6, not for building) touches every site in core/commit; `Path::to` there is the one-hop reading in code.
| hashed form | replaced by |
|---|---|
| `Paths::Hashed`, header hashes, `kdf("path", salt, Path)` | `Paths::Split { author, entries }`; `kdf("path", roles secret, blind ‖ tid)` |
| `Salted` in every section of a thing and copy; `Contents := [Opt(Salted), [Part*]]`; `CommitBlob::salted`, `salted_of`, `check_paths`; the stored and fire-payload `[[i, Salted]+]` | in a split commit `[[Part*], [PathKey*]]` in each section and copy (a key, not the path: the path stays in the header); `[Part*]` otherwise; a thing's path opened once and cached in the commit record as header data |
| the per-thing section split in `seal_commit` and copies (the issue's first class) | sections as in the clear form: one per thing, as built |
| `Acting::Each`, `View::acting_on(t)` | one purge author per commit, clear: `View::acting` |
| late-learned acting (`atomic::join_late`), `RecordHead::acting` | nothing: the author is clear; a thing's path is known once its secret or an encryption of its parts is held, its part examined again then |
| per-part hashed wait in `apply::examine` | the per-part wait on a part's own path (kept), plus "entry not opened yet": waits on the held role inputs and encryptions |
| `undo::undone_parts`' unknown-path case | a part its node cannot judge is not held |
| `Header::validate`'s hashed-beside-purge | `Split` on a role commit is bad input; a destroying request's header-only copy carries its thing's path key |
| hooks `Core::hashed_through`, `Core::forced_paths`; the four `validity::*hashed*` tests; the `commit_header` corpus' hashed entries | tests writing across two places for real; a wip-only forcing of the split form on every multi-thing commit to run the suites once; split entries in the corpus; vectors regenerated |
| the Interim's "where paths differ, one path for all" in `stated_path` | The engine's choice above |

The issue's second class (a part not held, its path unknown) goes because the path is in the header: a node holding the thing holds the key, or the encryption it reads carries it.

## Steps
Each leaves main working; spec and code together (notes/a1-spec/README.md, Order of the code briefs).
1. **The form** (step 2, the rest, first brief): spec/wire.md §4 (`Paths`, `Split`, entries, path key, `Contents` with path keys in a split commit, the destroying request's copy, bad input), §12; spec/crypto.md §5 a Path entry bullet; core/commit (`Paths::Split`, builder `thing_paths` with each thing's independent's roles secret, `author`; opening an entry); engine sealing (keys into sections and copies, kept through re-encryption), opening, `acting` one tid, the per-part "entry not opened" wait; every row of the table above but the last; the engine still writes one path (Interim), a test hook writes the split form.
2. **The engine writes it** (second brief): `stated_path` as The engine's choice; `act_as(X)` with no path through X for some thing fails `Permission`; the frontier lists commits with entries it cannot open; S's bodies carry the chain certificates of their parts' things only (spec/permissions.md §4, spec/sync-judgement.md §2 certificate blobs: "to each thing of the body under S"); the hooks go; issues/hashed-paths-forced-suite-gaps.md closes once the suites pass with the form forced (wip) and for real. Hand tests owed: a reader holding only a later epoch opens a re-encrypted split commit's path; a floor holder judges a lasting request on a dependent thing below its floor (drops the named copy in its snapshot); a destroying request beside a write on another actor's thing destroys at a dependent's holder.
3. **Step 3** (the walk by path) unchanged: each part with its own path; role commits state real paths (always one).
4. **Step 4**: one purge author per commit is the encoding already; a purge request is judged per thing it names along that thing's path; the author right reads members.

## Bytes
Header fields `signer`, `path`, `remains` (a tid 16 B encoded); accounts as today.
| commit | bytes |
|---|---|
| own things (one path `[0]`) | 19 |
| creation under a granted parent (`[0, D]`) | 35 (hashed form: 86 in the header, 56 in its two sections) |
| at or under the last of k holders | 19 + 16k |
| two paths: an own thing and a thing under D | 73 in the header (`Split` 56: 3 + an entry of `[]` 18 + of `[D]` 35), and about 37 per section (its path key) |
| n things, thing i's path listing k_i | 20 + Σ e(k_i), e(0) = 18, e(k) = 19 + 16k for k ≥ 1 (n ≥ 24: +1); +16 for a purge author other than the signer; about 37 per thing in its section |
A copy of a split commit adds about 36 B per thing whose parts it holds. Every section is 2 B smaller than built (no `Contents` head) outside split commits.

## The model
roles-model `paths` judges each part by (signer, its own path, `on`), so a split commit changes no reading: `World::split` writes one commit (grouped, so a list naming it names every part) with each thing's own path and one purge author. Hand world `a_commit_spanning_two_paths_is_judged_per_thing_as_one_commit_per_thing`: X writes T1 along [A] and A2 along its own grant, as one commit and as two at the same key; every reading (valid, purged, applied, roles) agrees across: no removal, H's removal of X from A (T1's part falls, A2's stands), K's removal from A2 (the reverse), a removal listing the commit, X's purge by author on T1 (T1's part alone). Order within a commit (a1-spec Open 14) reads only edge writes, which a split commit has none of (role commits are one path). `evidence` takes a held commit's other parts only on the same thing: a unit holding T1's part needs no edge of A2's path (asserted in the same test). Every grouped commit the generators make is on one thing (`World::commit` takes one `on`; `story::rebuild` keeps groups), so no generated world reads differently: the crate's and held-model's `_plain` and `_large` properties pass (paths, custody, epochs, vouches, `spec_evidence`). The model has no keys: who opens an entry is argued above, not modelled. Owed if Open 16 is taken as proposed: `Rules::author_thing` on in `fixed`, with deltas by their own thing in the `tiny` purge worlds.

## Rejected
- **Refuse or split a multi-path write**: rejected by the owner: a commit may span things reached through different actors.
- **The hashed form** (each path in its thing's sections): a path is header data; in a section it is missing exactly where the consumers above read it (a second "unknown here" case per consumer, `Salted` in every section, copies split per thing, paths learned late and kept past their parts).
- **A path key from the thing's own derived roles secret**: a holder of a floor on the independent holds only the independent's earlier roles secrets, never a dependent thing's derived ones (spec/crypto.md §3 derives from the read secret), so it could not judge a lasting request on a dependent thing below its floor.
- **The key in the header alone**: a section re-encrypted under a later epoch reaches a reader that lacks the entry's epoch (the rotator's history box need not carry it), which would read the content and wait on its path until a History add.
- **One search for a path serving every thing**: rests a thing's part on a longer route than its own (The engine's choice).
- **A clear primary path for the things it serves, sealed paths for the rest**: the primary's chain is shown to the other things' readers (rosters giving no role on them); it is safe only as the empty path, a second form saving about 18 B a thing on rare commits.
- **Every path sealed, one-path commits too**: about 18 B on every thing of every commit, and every header reader of a one-path commit needs a secret for what is shown to all alike; it is also what closing For Tess 3 fully would take.
- **Paths in the clear with members blinded per thing**: a blinded member resolves only by testing candidates a reader already knows, but a pending part needs the tid of a record it has not seen to fetch it; a per-commit blind keyed by B's secret is sealing at the same cost.
- **A purge author per thing**: a level-2 key per author, shown in the clear to every thing's readers, names a holder on another thing's chain; one author per write is what `act_as` offers.

## For Tess
1. Proposed property (spec/requirements.md, Commits or Confidentiality between readers): "A write may span things reached through different actors; it is one commit."
2. Open 16, the capability: may a write's author (`act_as(X)`) be a thing whose authority does not reach every thing the write writes? Proposed no (error). What a multi-thing write can do:

   | write | main | proposed |
   |---|---|---|
   | no `act_as`, things reached through different actors | accepted (one Interim path stated, each part judged by the signer's role by any route) | accepted (`Split`, each part along its own path) |
   | `act_as(X)`, X on every thing's path | accepted | accepted |
   | `act_as(X)` writing X and things under or held by X | accepted | accepted |
   | `act_as(X)`, X on some things' paths, not all | accepted where the signer may write X | refused (`Permission`) |
   | `act_as(X)`, X on no thing's path | accepted where the signer may write X | refused (`Permission`) |
   | a destroying request beside writes on things reached otherwise | accepted (Interim path) | accepted (`Split`, path key in its certificate copy) |
   | a role commit (rotation, re-seal) over things one path does not serve | accepted (Interim `[0]`) | the writer makes one per path (engine-made; the engine already writes one thing per role commit); a role commit with a `Split` is bad input |

   Lost: labelling a write as by an identity whose authority does not reach all it writes (no caller in chat, app, kit or CLI uses `act_as`); granting X a role gives the same label with a checked path.
3. What a reader of thing B learns of another thing T written in the same commit, beyond that T was written and by whom (which the requirement allows): in the clear form, T's last edge (the path's end holds a role on T; for an empty path, the signer does); in the split form, that T's path is not read off B's and how many things T's path lists (its entry size); in the hashed form, nothing. Each is a fact of T's roster, which gives B's readers no role, so "learn nothing of rosters that give no role on it" read strictly forbids all but the hashed form. (a) Accept both as what "written together" shows (*taken*). (b) Pad split entries to MAX_PATH_THINGS: closes the count, not the clear form's last edge nor the split bit; about 1 KiB a thing on split commits (a split commit writing the 6,500 things a blob holds would need about 6.8 MB of its 8 MiB `MAX_BLOB`). (c) Pad to the commit's longest: shows the longest only. (d) Seal every multi-thing commit's paths and pad: closes all, about 18 B (1 KiB padded) a thing on every multi-thing commit. Needs her word if the requirement is read strictly.
