# Owner becomes first admin: build plan
> Summary: Staged plan for notes/owner-removal-plan.md step 2: A (ownerless things derive) and B (one record form, one authority class; person, links, ephemeral, inbox) are built; C the remaining words in spec and code (derivation chain, `MAX_CHAIN_DEPTH`), D the public API, CLI and apps (conflicts with the API work). Inventory, tests per stage, risks.
> Tags: permissions, keys, perm, engine, spec, api

## What an owner did and what replaced it
| Owner role before | Built |
|---|---|
| Fixed the tid (record committed to the owner) | Record `{admin, nonce}` or `{key, nonce}`: the tid commits to the first admin, history only: it gives no power once the edge goes. |
| Inheritance: a role on an actor reached what it owned | Path rule only: the record edge is an admin edge from before every write, stored nowhere, removable. A role on F reaches T through F's record edge on T while it stands. |
| Plain things derived secrets from the owner | Derive from the first admin (the record chain). |
| Top authority (`Class::Chain`, irremovable, outranked edge admin, "an edge cannot name the owner") | Gone. Classes: edge admin, invite. Fights between admins: step 3; until then every thing has the hole of issues/ownerless-first-admin-backdate.md. |
| Person: a recovery key owned the account | A node is first admin; the recovery key holds a plain admin edge granted in the account's creation commit and recovers as an edge admin. A thief can remove it (accepted). |
| Link K "owned by the sharer" | K's first admin is the sharer's actor. |
| Move "never" | Grant then remove; no tid change (notes/moves.md). |

**The refused case**: a node MUST NOT remove or lower the last admin edge of a plain thing (refused locally, `Invalid`). Signed anyway it applies; the thing stays plain, its content stays readable through derivation by the first admin's holders, and nobody writes it. A stated limit, no machinery.

**Naming a first admin** needs write on it (a client check: the record itself needs no authority). Decided (Tess) below.

## Stage A: built
An ownerless thing (now: any thing) is created by its record alone and derives its secrets from its first admin's. Left as a stated limit: rule 2 of the model (a derived epoch written under is current until listed; its writer merges), issues/derived-write-merge.md (spec/crypto.md §4 states it).

## Stage B: built
One record form (`{ admin, nonce }` or `{ key, nonce }`), one authority class, every thing's first admin an ordinary admin. What it changed and why: notes/permissions.md (First admins, Implementation), notes/owner-removal-plan.md step 2. Points a reviewer should know:
- osis-perm reads record edges from the records (virtual): `Edges` holds what writes set and which record edges they removed; `Dense`, `EdgesAt` and `View` compose them. A late record for a written thing is handled by `Resume::fresh` (the record edge restored after the rollback), not a full evaluation.
- Changed expectations: `scenarios::{self_removal_dropped_with_sticky_residue, sticky_residue_of_dropped_grant, audit_drops_removal_not_self_grant}` and node `validity::sticky_residue_spec_perm_5_1` (a write a node sustains by its own grant below is no longer dropped when the owner-chain class would have fallen: one class); a group's own live label is an inbox candidate for blobs about it, so node tests whose premise is a group label that is no inbox (`revokes::*`, the junk and fill fixtures) name one elsewhere (`Net::name_inbox_elsewhere`).
- The inbox and `label.0` cross-publish follow the record chain through standing record edges (`Core::inbox_chain`, `published_by_actor`): the plan's "home label only" text would have cut outsiders' grants to groups (a sender knows a holder by its `keys.0`, not its `label.0`). Only a label a held actor's `keys.0` names is an inbox to the fill order (`InboxActors::named`): a fresh joiner otherwise fetched a chat's unopened epochs before its newest messages.
- The recovery key's card is a commit of its own (signed by the key); `Engine::certificates` places the cards of a group's key-actor holders with every admin's certificates, so the paired node places it when the creating node loses its disk first (sim `disk_loss`).

## Stage C: the words in spec and code
Renames only; passes the gate alone. Spec: Section `[owner*]` becomes `[chain*]`, the **derivation chain** (the record chain up to the first actor with secrets of its own; only keys use it); `MAX_OWNER_DEPTH` becomes `MAX_CHAIN_DEPTH`; delete base reworded; overview "ownership"; crdt.md "owning" becomes "carrying". Code: `Owner`, `OwnerChain`, `owner_chain`, `section_owners`, `owner_actor`, `Owners`, test names (`jumped_owner_*`, `derived_n_follows_owner_below_cap`, `ephemeral_owner_chain_travels_*`, `owner_rcpt`), model identifiers; optionally the CRDT owning-delta names (`any_owner`, `owner_received`, `owner_dots`) to clear the grep. Notes: permissions, sync, crypto, node, ephemeral, data-model, testing, testing-map, whole-commits, moves (move = grant then remove), realms (made in a realm: the realm is first admin; resumes), owners and owner-removal-plan (step 2 built); issues: ownerless-first-admin-backdate (now every thing, until step 3), creation-record-ordinary, eph-unify wording.

## Stage D: API, CLI and apps
Conflicts with the API work (notes/api-design.md checklist applies); A-C touch only the doc-hidden aliases and their tests. Delete `create_owned_by` (trees: `create_with_admin(x)`, a first admin the same commit creates counting through its own), `create_ownerless` (chat: `create()` and a durable write), `owner_of`, port methods 7 and 43, CLI `ownerless` and `info`'s owner line. No first-admin read in the app API: it is history, and `grants` lists the record edge while it stands. Chat tells an account from a team and a link key through `grants` one level down (issues/api-after-owners.md); the app's who-can-see starts from holders. `Admit::Own` keeps B's meaning; its name and CLI word go through the checklist. `Tier::Owner` (the node's operator) and the store's file-owner check are other meanings: rename only if the concept warrants it. notes/api.md, cli.md, client-port.md, chat.md, app.md; delete issues/api-after-owners.md (dispute-call room moves to notes/api.md).

## Risks, as they stand
1. **Key access after a grant is removed**: modelled (`D0_fa_flip`, `D0_fa_both`) and stated (spec/crypto.md §4 Key access: a removed actor edge is no standing; notes/crypto.md). The engine judges key access over standings (`Timeline::standing_since`, record edges at `None`).
2. **Walk cost of a record edge per thing**: record edges are virtual in osis-perm (read from the records; a written edge overrides), so a plain thing costs the edge state nothing; audits reach by edges with the first-admin index (`Owners::owned`). Measured (release; main against the branch): perm `bench_10k_edges` 439.9 G against 440.2 G instructions (`tools/icount`); node `scale::role_change_and_open_cost` opens 232-244 ms against 172-175 ms, a grant with 10^4 commits 0.70 against 0.97 ms (wall, loaded box); sim `many_labels` at 100 labels within 5-15% wall, first sync bytes up 2.82 against 2.63 MB; `chat_members` m=30 joiner 737 against 373 ms, 510 against 454 KB down, store 61 against 54 KB per member. A million leaves under one actor: notes/testing.md (Scale checks, record edges per thing); `Dense` builds its adjacency sorted once per holder (a linear scan per edge made it quadratic).
3. **Interim hole**: until step 3 a removed admin can backdate and take back any thing, accounts included (issues/ownerless-first-admin-backdate.md). Pre-release; step 3 next.
4. **Derivation after the edge goes**: the refused case (a local refusal, not modelled). A derived write after the switch: issues/derived-write-merge.md.
5. **Record-chain reads that outlive removal**: `admit own` (hosting only, ciphertext: kept static); the inbox fallback and the `label.0` cross-publish go up the chain only through record edges standing at the writer.
6. **Depth**: nothing resets the `MAX_OWNER_DEPTH` cap; chats add two links. Check app trees stay far under 64.

## Decided (Tess)
- Anyone with write on G may make a thing whose first admin is G (G's admins administer it, its writers write it). `create_with_admin` checks write on G.
