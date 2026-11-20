# One path per commit
> Summary: Proposal (not built, not in spec; the coordinator decides): a commit states ONE path, to the place it acts from, and writes that thing and things one hop past it; the hashed per-thing form goes, and a write whose things need two paths is refused whole. Who reads a path without opening a section; every multi-thing commit the engine and apps write, under the built rule and this one; whom a write is by (`act_as`, a1-spec Open 16); what steps 2 to 4 build and delete; bytes; the model's reading (roles-model `paths`: `World::stated`, variant `author_thing`); what needs Tess.

**Principle: a commit acts from one place. Its path leads there; everything it writes is that thing or one hop past it, and it is by one of the things the path names.** A path is a fact of the header, read by every node that holds the header, so it is stated once, in the clear, for the whole commit.

Status: *proposed*. Built today: notes/a1-spec/README.md (step 2), spec/wire.md §4 (one path in the clear, else a salted hash per thing).

## Who reads a path without opening a section
Every reader that holds the header, for every thing of the commit it holds. Nobody else: a store or a node keeping the unit unread opens no blob (it reads the blob prefix: delete commitments, expiry), so it reads no header and no path.

A reader reads a thing's path where it has no section of that thing (late, stripped, purged, forgotten, covered, never sent to it):
- what a pending commit waits on (`apply/waits.rs` `pend_needs`: the things its path lists), before any part is opened;
- the validity of every aspect row of the header, body or not (`apply/atomic.rs`: `part_valid` over `h.aspects`; a part joining late, an undo, a replaced creation and held-model's `held_set_decides` all read a part that is not there);
- purge: the author of a target delta and the path of the request, which names things in the header's `purge` field and need write no part on them (`retention/purge.rs` `acting`);
- level-2 delete keys of a delta (`retention/names.rs`, `retention/freed.rs`, `sync/mod.rs` level-2 row);
- a cover's facts: the purge author of each commit it absorbs, whose bodies then go (`retention/snapshot.rs` `header_fact`);
- certificates today and evidence at A2 (`sync_ids/certs.rs`; notes/write-path-design.md §2: the closure over the paths of the commits a unit holds, computed by its readers per held commit, body kept or not);
- the indexes by acting thing, listing rows, stamps, fired signals.

So a path is header data like an `aspects` row. A path kept in a section is missing exactly where these read it; every gap of the hashed form (issues/hashed-paths-forced-suite-gaps.md) is this one fact. The header has no per-thing confidentiality, so a per-thing path has no place to be: in the clear it shows one thing's readers another thing's holder chain; sealed per thing it is a second sealed field with its own "unknown here" state.

## The rule
- **Path**: a commit states one path [A1, …, Ak], k ≥ 0, and one purge-author index. Its **end** is Ak (the signer S where k = 0).
- **Members** for a thing T it writes: [S, A1, …, Ak, T]; where T is the end they stop there: [S, A1, …, Ak]. Hops, descent, edges, the last edge, a self-removal ending at its holder, "a thing named twice is invalid": all as notes/a1-spec/permissions.md §1 reads members. "For a commit by a key actor on itself, [S]" is the case k = 0 of the same sentence.
- So one commit writes: its end; the things the end holds a direct grant on; the things descending from the end by record edges. A thing listed before the end, or reached from no hop of the end, has no valid members (named twice, or an edge nobody set).
- **Nobody learns a chain that is not its own thing's**: for every thing written the stated path is that thing's own holder chain (with the thing itself last, for the end). This is why things may hang only from the end: a thing hanging from an earlier member would show its readers the holders after it, which give no role on it (spec/requirements.md, Confidentiality between readers).
- **Form**: `Path := [index, tid*]`, alone. Two statements with the same members (D written alone as `[]` or as `[D]`) are judged alike; the engine states the shorter. No decoder rule tells them apart: it would buy nothing.
- **A write whose things need two paths is refused whole** (`Invalid`, naming two of the things), as a write with two expiries or mixing durable and ephemeral is (osis `Write`: "What cannot share a commit fails `commit` ... writing it as several commits is up to the app"). spec/requirements.md already says a write is one commit or is refused, and that a write too large is "refused whole, never split".
- The engine searches ONE path serving every thing of the commit (each thing at the role its aspects need), not a path per thing compared afterwards: two per-thing searches can pick different routes where one route serves both (D by an admin route for an admin-only aspect, its child by a shorter writer route).

### What it makes one path
The built rule lists the granted thing D on the path of what is under it and not on D's own, so every commit writing D and something under D "differs by necessity". Here that commit states `[D]`: D is the end, the child hangs from it by its record edge. Deeper things already hung by descent (a mint ancestor two or more record edges up is never listed); the end is the same reading at zero steps.

| commit | things | built rule | this rule |
|---|---|---|---|
| edit of one thing | 1 | one | one |
| dependent creation under the signer's own things (`created.0`, parts, the holder's `holds.0` or other aspect with the strong) | new, holder | equal `[]` | equal |
| dependent creation under a granted D (a message in a shared room) | new `[D]`, D `[]` | differ | one: `[D]` |
| the same, D reached through holders X.. | new `[X, D]`, D `[X]` | differ | one: `[X, D]` |
| creation under a dependent C below granted D | new `[D]`, C `[D]` | equal | equal |
| edit of D and of a thing under D; of siblings under D | | differ; equal | one; one |
| independent thing with the account as mint admin, held from a granted D | new `[]` (descent), D `[]` (grant) | equal | equal |
| creation with its mint admin under one end and its strong in a thing under another (CLI `create --admin` with another `holder`; kit `grow` tagging with an own tag a thing made in a shared group) | | differ | two paths: refused |
| app `Write` over things of two shared things, or own things and things under a granted D | | differ | two paths: refused |
| hold, unhold, tag: one `holds.0` | 1 | one | one |
| a grant, demotion, removal, finalize, invite grant: `roles.0`, `secrets.0`, `keys.0` of one target; a redemption's grant and self-removal | 1 | one | one |
| account creation (P, its root, profile and inbox records, signed by P); pairing, device change, rotation (P's `keys.0`, the root's `account.0`, `secrets.0`) | signer and what it minted | equal `[]` | equal |
| link creation: a commit per thing, but the seed thing with the root's `holds.0` | seed, root | equal `[]` | equal |
| vouches, addenda, listings owed over several things | one commit per thing | one | one |
| snapshot, own cover | 1 | one | one |
| undo | the undone commit's things | as that commit | as that commit (by another signer reaching them two ways: refused) |

A thing never moves (notes/moves.md), so no commit re-parents.

Counted with a probe in `stated_path` over the default tests: osis-engine, 4,910 commits writing two things or more, 13 differing under the built rule, 12 of them one path here (creations under a granted parent), 1 with two paths (`validity::a_write_states_the_holders_it_goes_through_spec_wire_4`, a batch built by hand to differ); osis, osis-chat and osis-cli, 1,444, 1 differing, none here. No engine flow writes two paths: every flow that spans ends already writes a commit per thing in one transaction (`flows/links.rs`, `flows/vouches.rs`, `flows/signing.rs`).

**What stays two paths**: one app write spanning two places the signer reaches differently: two shared things; a shared thing's children and the signer's own things; a thing made under one and held or tagged from another. After A4 (the account a listed thing) the split is the same one level down (`[A]` own, `[A, D]` under D).

### What users lose, and the question for Tess
Atomicity across two places: such a write is two writes, and another node may apply one before the other. Nothing in the engine needs them together: a creation's hold is checked at the transaction's end (`wrote_on`), not per commit, so a thing made in one commit and held by the next in the same transaction is sound.

The cost is an asymmetry an app meets late: a write over a room's messages and the writer's own things is one commit in a room the writer made (everything descends from the signer) and refused in a room it joined. spec/requirements.md does not promise such a write today in so many words ("A commit may touch thousands of things, of any reader sets"; "A write is one commit or is refused"), but the first sentence reads as if any set of things will do. **For Tess**: add the property "the things of one write are all reached the same way: one thing its writer reaches, what that thing holds directly and what was made under it; a write spanning two is refused whole, never split", and say in the API docs where it bites. The alternative that keeps any set of things in one commit is the hashed form, at the cost below.

## Whom a write is by (`act_as`, a1-spec Open 16)
**A write is by one of the things its authority passes through, the thing written included; nobody names a thing its authority does not pass through.**
- The purge author is a member: the index names S or a listed thing, and the thing written is named by listing it last (`[.., T]`, index k): no index value of its own. `act_as(X)` asks the engine for a path through X; the engine finds it (to X, X, on to the thing), as built.
- **X holding no role on the thing**: a write error (`Permission`, needing write through X). Main accepts it on the signer's write on X alone, which the thing's readers can check only by X's roster, a roster giving no role on the thing (spec/requirements.md, Confidentiality between readers: "nothing of rosters that give no role on it"), and which evidence along stated paths (A2) does not carry: an unchecked label. What it gave: an identity label on a thing that identity cannot reach. Granting X a role gives the same with a checked path. No caller in chat, app, kit or CLI uses `act_as`.
- **X the thing written** (T on T): allowed, the path listing T last. It is "by the thing itself": any valid request by author T on T holds the right (T is a member of every path to T), and level 2 is T's write secret, which every writer of T holds. A commit acting as a room D that makes a thing under D writes D's own part by D too, so refusing T on T would refuse that commit.
- A request by author holds the right over a delta iff the author is among the request's members for that thing and the request is valid (notes/write-path-design.md §1, What a purger must hold, with "members" for "path").

## Rejected
- **Keep the hashed form and close its gaps**: the path sits where header readers cannot reach it, so each consumer above needs a per-thing "unknown here" case for good: two header forms and a MUST no decoder can check; `Salted` in every section and copies split per thing; section membership differing by form; paths learned late and kept past their parts; validity of a part not held differing by form; purge requests barred from the form; a level-2 key per purge author; listing rows, held commits, level-2 rows and signals reading one actor; both forms in vectors, fuzz corpus and hooks. All of it exercised only by rare commits. About 107 B more than one path per two-thing commit.
- **Every thing's path in the clear**: the header names tids unblinded (the thing blind of spec/crypto.md §7 blinds delete commitments, not header tids), so a reader of A would read the holders through which the signer reaches B: rosters that give no role on A. It would weaken Confidentiality between readers, and keeps per-thing acting in every consumer.
- **A thing's path sealed in the header under its read secret**: closes the section gaps, keeps the unknown state (a header reader without that thing's secret at that epoch), adds a sealed field and a key use per thing.
- **Paths in sections only**: every header-level reader above has none.
- **Things hanging from any listed member** (own things and a room's in one commit under `[D]`): shows the own things' readers that their writer holds a role on D.
- **Always listing the thing entered by grant** (D written alone as `[D]`): 16 B on every write of a granted thing, and an own independent thing held from a granted D, one path today, would split.
- **The engine splitting a write per path**: atomicity lost silently, `commit` returning several commits, an undo reverting half. Refusing is what `Write` does for every other clash.

## Steps
Each leaves main working; spec and code together (notes/a1-spec/README.md, Order of the code briefs).
- **Step 2, the rest.** spec/wire.md §4: `path` is one `Path`; `Paths`, the hashed bullet, `Salted`, `Contents`' head (`Contents := [Part*]`), the copy's "one per thing where hashed", §12's hashed line and the `"path"` kdf label go; the draft's §1 Path takes the members sentence above. Engine: `stated_path` finds one path for the commit or fails `Invalid`; `act_as(X)` with no path through X fails `Permission`; `interim_path` stays only for role commits, rotations, re-seals and a fire valid by its thing's setting (step 3). osis `Write` doc: the third "cannot share a commit" bullet. Deleted: `Paths::Hashed`, `Salted`, `Acting::Each` (`Acting` is one tid: `View::acting_on(t)` becomes `acting`), `CommitBuilder::thing_paths`, the per-thing split in `seal_commit` and in copies, `CommitBlob::salted`, `salted_of`, `check_paths`, the stored and fire-payload `[[i, Salted]+]`, `RecordHead::acting`, `atomic::join_late`'s learning of an acting thing, the per-part hashed wait in `apply::examine`, the unknown-path case of `undo::undone_parts`, `Header::validate`'s hashed-beside-purge, the hooks `Core::hashed_through` and `Core::forced_paths`, the four `validity::*hashed*` tests, the hashed entries of the `commit_header` corpus; vectors regenerated. The consumers reading "the actor" from the first thing (listing row, `HeldCommit.acting`, the level-2 row, fired signals) are then right as written. issues/hashed-paths-forced-suite-gaps.md closes.
- **Step 3.** The walk by path: the engine hands osis-perm `paths` each part with the stated path less a trailing `on` (`Part.path` is the things between signer and `on`, unchanged); role commits state real paths (one target, or the signer and what it minted: always one path); the Interim and Acting go.
- **Step 4.** One purge author per commit: header `keys` holds at most one level-2 key (the Interim check in `validate.rs` becomes the rule); a purge request acts along the commit's path on every thing it names, so the things it names are those one commit can write; the author right reads members.
- Later steps unchanged; step 5's evidence of a commit is the edges of one path and each thing's descent.

## Bytes
Header fields `signer`, `path`, `remains` (a tid 16 B encoded); accounts as today (after A4 one more listed thing, 16 B, on each line).
| commit | bytes |
|---|---|
| ordinary, own things | 19 (16 + `[0]` 2 + 1) |
| dependent creation under own root | 19 |
| dependent creation under a granted parent | 35 (hashed form: 86 in the header and 56 in its two sections) |
| a granted thing written alone | 19 |
| write at or under the last of k holders | 19 + 16k |
Every section is 2 B smaller (no `Contents` head).

## The model
roles-model `paths` judges a part by (signer, path, `on`), that is by members, and this rule leaves every part's members as they are: it changes only how one stated path gives each thing its part's path (drop a trailing `on`). `World::push`, `joins`, the hops of a descent, `remains` and `Rules::last_hop` read the same members as before: for the end thing the last edge is the hop from A(k-1) to Ak where that is one edge, as for path `[A1..A(k-1)]` on Ak today. `World::stated` is that mapping, with the hand world `a_commit_writes_its_paths_end_and_what_hangs_from_it` (the end, its child and grandchild along one path, cut alike by a removal; a thing the end does not reach and a thing listed before the end are invalid). Whom a write is by adds one reading, as the variant `Rules::author_thing` (off in `Rules::fixed`): an index one past the part's path names the thing written and a request's chain holds its thing (`a_write_by_the_thing_it_writes_is_purged_by_any_writer_of_it`; without the variant nothing is purged). `fixed` is untouched: default tests and the gate's paths properties (`random_worlds_hold_large`, `small_family_holds_large`, `small_worlds_hold_plain`) hold. Owed if the proposal is taken: `author_thing` on in `fixed`, with deltas by their own thing in the `tiny` generator's purge worlds.

## Not settled here
- The path of a fire valid by its thing's setting alone (its signer holds no role): step 3.
- Whether a decoder should refuse the longer of two statements with the same members: taken as no.
