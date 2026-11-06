# Revocation without an arbiter
> Summary: Lowering or removing a role invalidates the holder's writes the remover had not received (spec/permissions.md §5.1, the frontier), so the result depends on how well one node had synced. No node can know it has every commit. Collects Tess's concerns: a removal reaching things the remover can't read or doesn't sync, whole groups of history lost, the "seen by an authorized node" rule that was dropped, and what catching up should mean with peers only. Needs Tess's input.
> Tags: permissions, sync, spec, tess-call

## The rule today
A removal carries a **frontier**: the commit IDs of the removed holder's writes the remover had received. Every write of the holder's below the removal that isn't listed turns invalid everywhere. Timestamps can't decide, since a removed holder could forge old ones. Before stamping, `set_role` catches up with the peers reachable now, syncing every group below in full, or headers only for groups marked log only (issues/revoke-needs-whole-tree.md); `set_role_now` does not.

## Tess's concerns
1. **No arbiter.** "I have all the commits" isn't a thing osis can know. A write made a moment ago on Bob's offline node is as legitimate as any. Syncing with every node that may write is impractical: another account's nodes may be unknown, or new ones made offline from cold keys.
2. **Groups the remover never synced.** Possibly years of Bob's content there is wiped by one removal, which is worse than losing recent edits. spec/permissions.md §5.3 says so outright ("uncompacted writes by the demoted holder under the labels not synced are then lost").
3. **Reaching what the remover can't read.** Can a removal take away Bob's write on things the remover can't read, through an actor or group it administers? Check, and say whether that's ever right.
4. **Reaching what isn't synced with the remover.** A thing the remover could read but which only Bob and Carol sync: removing Bob wipes all his history there.
5. **"Seen by an authorized node before the removal stays."** The earlier rule. It was dropped as an agent's call, not Tess's: notes/permissions.md (Revocation, and the roles-model findings) records third-party witnesses failing to settle in about 14% of random histories (period-2 loops) and self-witness holes (a backdated grant witnessed only by its beneficiary; forged grants vouching for each other). Reopen with modelling: is there a version that converges?
6. **What catching up means with peers only.** Built as "with whoever is reachable now", which never fails for lack of a peer (Built, below).

## API, decided with Tess
- `SyncFirst` goes, `Backdate` with it.
- Catching up is the default. Not waiting is an ordinary choice, not mainly for hostile devices, and doesn't need to be async. Built as two calls (agent's design): `set_role(..).await` catches up with whoever is reachable, then writes; `set_role_now(..)` is synchronous and writes at once.
- A caller wanting a time limit wraps the first in its runtime's timeout and falls back to the second.

## Built
- `set_role` / `set_role_now`; `revoke_link` / `revoke_link_now` (an offline node must be able to end a leaked link); `remove_node` catches up and has no twin (`remove_node` at once: `set_role_now(me, node, None)` then `links`). Chat: `kick` / `kick_now`. CLI: `--now` on `set-role`, `node rm`, `link revoke`, `chat kick`;  `SetRoleOpts { retain_copy }` only.
- "Caught up" per label in scope (notes/api.md Demotion and catching up): with saved peers, `Synced` as `Required` waited for it (unchanged); plus every other reader on a connection this node dialed with the label open, idle (last pass ended with nothing outstanding), judged as connected at each look. Nobody reachable: done at once. Stranded: `Unsynced` at once.
- Gaps: a reader that dialed this node (a served session) is not judged (the serving side keeps no "pass finished" state: `Served`, core/node/src/sync/serve.rs), so in the usual direct-link case the link's maker catches up with nobody (only the redeemer, who dialed, judges the maker); the reader's pushes arrive as it makes them, but nothing confirms it has sent all. A saved peer out of reach still waits forever (as `Required` did): the caller's timeout and `set_role_now` are the way past it.

## Directions to weigh
- Judge readers that dialed in (last review's recommendation): give the serving side a "pass finished" state so a served reader counts as caught up, before direct links are the common way to share; today a direct link's maker catches up with nobody.
- Catch up with headers only for every group below that this node doesn't hold. The mechanism exists, and it addresses 2 and 4 for reachable data.
- Audit only groups the remover holds or read, leaving others until someone who holds them removes the holder. A hostile holder keeps those writes meanwhile.
- A converging witness rule (5).
