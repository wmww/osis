# Path form
> Summary: How a commit states the path each thing it writes is judged along (built; spec/wire.md §4 field 2, spec/crypto.md §5 Path entry): one path in the clear where every thing's own path is read off it and it tells no reader a roster fact it could not read; else the split form, one purge author in the clear and each thing's path sealed under its independent's read roles secret, the key in every encryption of the thing's parts (padded entries). Who reads a path, per consumer; the engine's choice; the clear-form rule and its argument; padding and what stays visible; `act_as` (Open 16); bytes; what is left; what needs Tess.

**Principle: a thing's path is header data, readable exactly by the nodes that judge that thing's parts.** A write is never refused or split for its paths (the owner's rule): one commit may write things its signer reaches through different holders.

## Who reads a path
A thing T's path is read by every node that judges T's parts: T's holders, who hold the read roles secrets of T's independent (spec/crypto.md §3, §4: derived, boxed, or below a floor from history entries). A node holding the header but no secret of T's independent at the entry's epoch and no encryption of T's parts never needs T's path: T's content applies nothing there (spec/commits.md §4 Outside the node closure).

| class | judges T's parts | opens T's entry |
|---|---|---|
| reader, writer, admin of T or of a holder of T; reader of a sync ID whose unit holds T | yes | yes |
| holder of a floor on T's independent, epochs below it | role parts, lasting requests | yes: history entries carry the independent's earlier roles secrets (why the key is the independent's, not a dependent thing's derived one) |
| holder lacking the entry's epoch | once it holds a part | by the key in any encryption of T's parts (a re-encryption under a later epoch, a copy); with none, T's parts are judged invalid until a key or the epoch comes (`apply::paths::refresh`) |
| reader of another thing of the commit, a store, a keyless holder | no | no |
| node needing a destroyed T | the destroying request | by the key in the request's header-only copy |

## One path
- A `Path` `[i, A1, …, Ak]` writes its end Ak along A1..Ak−1, and every other thing one hop past Ak (the things the end holds a direct grant on, or descending from it by record edges). `osis_commit::Path::to` reads a thing's holders off it; `Path::one_of` finds the one path serving every thing's own path, if any.
- **What it tells other readers** (For Tess 3): every thing's chain up to the end is a prefix of each reader's own path. On the empty path every thing hangs off the signer, which "written by the signer" shows already (a reading of the requirement: strictly, that the signer's role is its own edge and not through a holder is a roster fact; reading it so would split every multi-thing write of own things). On a longer path, a thing T one hop past the end shows its last edge (the end holds a role on T) to the readers of every other thing W written. The clear form is used only where each such W's readers read that edge already:
  - T derives its read secret from W (W on T's record chain up to T's independent): W's readers read T whole, roster and record; or
  - T's last hop is by record edges (T made under the end) and W's record chain holds T (W made under T): W's readers hold W's record chain, T's record on it.
  - Otherwise, a grant by the end on T, or T independent of W, the commit goes split though one path would serve. A creation of a dependent thing under a granted parent D (`[D]`) and under the account root (`[0]`) stay clear; a creation of an independent thing under a granted D writing D's `holds.0` goes split (D's readers do not read T's record).
  - `engine::write::clear_tells_nothing`.

## The split form
`Split := [Opt(tid), [bytes+]]`: the purge author (absent: the signer), then one entry per thing written in aspect order. Entry of T: XChaCha20-Poly1305, nonce zero, empty AD, under T's path key `kdf("path", read roles secret of T's independent at the epoch T's sections go under, blind ‖ tid)`, of the canonical `[tid*]` T is written along (T last where it is the purge author), zero-padded.
- **Every encryption of T's parts carries T's path key** (`Contents := [[Part*], [PathKey*]]` in a split commit): sections, re-encryptions, copies; a header-only copy of a split commit destroying T carries T's key in a section of no part (`osis_commit::seal_header_only`). Keys a writer adds beyond its parts' things are harmless (it could publish them); a key not opening its entry makes its encryption hold nothing.
- **Bad entries** (a list breaking `Path`'s rules, T listed other than last, the purge author not among T's members): T's parts hold nothing at every reader of T (`CommitBlob::settle_paths` drops them once the aspect list resolves; `View::paths` records `false`). An entry under the wrong key, or swapped with another, opens at nobody: T's parts are never valid anywhere; other things stand (`osis_commit` `a_forged_entry_harms_only_its_own_thing`).
- **Padding** (For Tess 3; `osis_commit::ENTRY_CLASSES`, arbitrary-values: at 0 classes (no padding) the size shows the count of holders exactly; at infinity (`[MAX_PATH_THINGS]` alone) about 1 KiB a thing, too much for every split commit): each entry is padded to the smallest of 4, 16, 64 listed things at or above its count, 81, 273 or 1042 bytes. Real paths list 0 to 3 things, so every realistic entry is 81 B and shows nothing; what stays visible: that a thing's path lists more than 4 (or 16) things, and, to every reader, that the commit is split (its things' paths are not one `Path` the clear-form rule allowed). Options for Tess: accept the clear form and the split bit (drop the rule in `clear_tells_nothing` too, saving bytes on rare commits), pad (built), or always seal multi-thing commits (about 83 B a thing on every such commit).

## Per consumer
- **Judging**: the old walk (Interim) reads the one purge author (`View::acting`) on every thing; a split commit's part on a thing whose path is not known here (`View::paths`: `true` known, `false` bad, absent while it opens nowhere) is invalid (`validity::Judge::part`). A held part always carries its key, so only parts not held can be undecided; `Indexes::paths_unknown` lists those commits, opened again as role inputs move (`paths::refresh` in `rejudge_all` and after `flows::retake` in `atomic::rejudged`), and at load.
- **Waits**: a commit awaits its purge author's record (as one clear path's actor); no per-part path wait (held parts always know their path).
- **Purge, level-2 keys, cover facts, listings, stamps, signals**: the one purge author, in the clear (`Header::purge_author`).
- **Undo**: a part not held on a thing whose path is not known here: the commit is not undone there (`undo::undone_parts`, `NotKept`).
- Role commits state one path (a `Split` on kind 1 or 3 is bad input); the engine writes one thing per role commit.

## Whom a write is by (`act_as`, a1-spec Open 16)
- One purge author per commit; it must be among each thing's members in a split commit (else that thing's entry is bad).
- Built (Open 16 undecided): `act_as(X)` with X on every thing's path states the real paths with X as purge author; where some thing's path does not go through X, the engine states the Interim `[X]` for the whole commit (`engine::write::stated_paths`, marked Open 16), as main's Acting check accepts it. Proposed: refuse it (`Permission`); the owner has not agreed.

## The engine's choice
Each thing's own shortest path (`write::path_with`, memoized per (thing, role)), through X where acting for X; the clear form where they are read off one `Path` and `clear_tells_nothing` holds; else split. Never a longer route for one thing so one path serves all (a part rests on its stated path's edges alone). Interim `interim_path`: role commits, rotations, re-seals, a commit where no path gives the role (a fire valid by its setting), the Open 16 case. `validity::every_stated_path_is_a_chain_of_held_edges_spec_wire_4` checks honest paths are held chains.

## Bytes
`signer` 16, `path`, `remains` 1 (from `thing_cost` and `osis_commit` tests):
| commit | path bytes (+ signer and remains: 17) |
|---|---|
| own things (`[0]`) | 2 |
| dependent creation under the account root (`[0]`) | 2 |
| dependent creation under a granted parent (`[0, D]`) | 18 |
| at or under the last of k holders | 2 + 16k |
| a write of D (by grant from the end) and a thing D holds by grant (clear rule refuses) | split: 3 + 2 · 83 = 169 (author the signer), each section +38 (its key) |
| two paths | 169; +16 with a purge author other than the signer |
| n paths | 3 + 83n for paths of at most 4 holders (n ≥ 24: +1 head byte); 275 / 1044 per entry past 4 / 16 holders |
A copy of a split commit carries 38 B per thing whose parts it holds. Sections of one-path commits carry no key list.

## Left (notes/a1-spec/README.md step 2)
Owed tests: a reader holding only a later epoch opens the path from a re-encryption; a copy-only reader judges; a destroying request beside writes on another actor's thing destroys at a dependent's holder; a hostile split commit cannot make two honest nodes disagree for good (forged-envelope cases); the owner's rule through the `osis` API (two accounts, a write through a holder and on an own thing, one commit, applied at the other account). Purge per thing along each thing's own path (step 4 reads members). The frontier listing commits with entries the remover cannot open; S's bodies carrying only their parts' things' chain certificates (step 3 / A2).

## Rejected
- **Refuse or split a multi-path write**: the owner's rule.
- **A salted hash per thing, each path in its sections**: a path is header data; in a section it is missing exactly where header readers need it.
- **A path key from the thing's own derived roles secret**: a floor holder holds only the independent's earlier roles secrets.
- **The key in the header alone**: a re-encryption under a later epoch reaches readers lacking the entry's epoch.
- **One search for a path serving every thing**: rests a part on a longer route than its own.
- **A purge author per thing**: a level-2 key per author names a holder on another thing's chain.

## For Tess
1. Proposed property (spec/requirements.md): "A write may span things reached through different actors; it is one commit."
2. Open 16: may `act_as(X)` name an X not on every thing's path? Built: main's behaviour (Interim `[X]`); proposed: `Permission`.
3. What a reader of one thing learns of another thing written with it: built, the clear form only where it tells nothing (empty path read as "by whom"), padded split entries (the split bit and counts past 4 holders visible). Options above.
