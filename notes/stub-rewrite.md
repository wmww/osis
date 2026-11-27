# Stub rewrite: owed and open
> Summary: What the stub rewrite (design: notes/stubs.md; rules: the spec) still owes, and its open questions for Tess, each with options and the working answer as built.

## Status
On main: spec, engine, osis-sync and the models. Tess approved the shape and took the working answers below; she may revise any. A decision is recorded by changing the spec and deleting its question here.

## Open for Tess
1. **How a holder that cannot open a commit by its wrap gets in** (a grantee, a re-sealed or sync-only holder). (a) A notice sealed by a serving reader on one connection, never stored; (b) the commit's blob key sealed to each told holder inside the commit (the form Entry.tla checks); (c) entry boxes in X's steps. Working: (a), one step past the model (notes/stubs.md, Rejected, for (b) and (c)).
2. **Link keys' entry boxes** count a thing's link keys to every store (spec/wire.md §8: one box per static entry per step). (a) Keep; (b) move link keys to the notice form: the redeemer proves K by role at a reader, so a link is redeemable only where a reader of K is online. Working: (a).
3. **A weak reference's stub is followed**: one more followed sync ID per weakly referenced independent thing (one per author profile in a chat). (a) Followed, with an n/10n test; (b) carried but not followed. Working: (a).
4. **Removals reach readers by chain stubs alone**: a hop's removal reaches readers by chain stubs alone; a reader of R by its own grant may accept a stolen key's write until the removal reaches it (notes/stubs.md, the chain-hop line). (a) Accept it under "removal binds honest nodes that receive them"; (b) push removals into every unit whose keys open through the hop. Working: (a).
5. **No following by the public entry**: a unit that lost its role on X learns X turned public only once a node syncing both logs X's stub. (a) Accept; (b) follow X's sync ID by the public entry. Working: (a).
6. **A departed member is told by notices** (its removal's copy, and the public's edge served). (a) Notices; (b) serve it X's role entries up to its departure, which fails where those are wrapped under epochs it lacks. Working: (a).
7. **A strong enters by the node's role**: a strong to X that its unit carries enters X read or kept unread by the secrets the node holds; the model gives the node X whole only where a unit's keys open X. (a) As built (it keeps kept-unread stores); (b) the model's rule, a reference at sync giving a stub alone. Working: (a), the differential oracle runs it as `Rule::BUILT`.
8. **A sync-only stub follows nothing of X**: it is the sync copies under the carrying unit (spec/sync-set.md §2 Holding a stub). (a) As built; (b) follow X's sync ID kept unread. Working: (a).
9. **Pairing hands over no trust records**: the new node takes sides as commits reach it (spec/permissions.md §5.1), so a dispute the pairer had settled may show again there, against "one side per fork, sides stick". (a) As built; (b) hand over the pairer's trusted lowerings with the locator. Working: (a).
10. **An entering node names S in ByRole to every peer it meets**, a leak of its interest in S (spec/sync-hostile.md §1). (a) As built; (b) only to the locator's or signal's peers, which makes a stale hint final. Working: (a).
11. **A grant signal's peers are a beacon**: anyone holding the holder's card fires a signal naming peers of its choosing, and the holder's reading nodes dial them while it is held, so the sender learns such a node is online and the address it dials from. (a) As built; (b) no peers in a signal: a stranger's grantee meets X's readers only through its own peers; (c) dial a signal's peers only once the app accepts the signal. Working: (a).
12. **The inbox**: Tess's rule is that an inbox is a thing of its own, held by a strong from what takes grants there, so its setting governs nothing else; spec/sync-inbox.md §1 still lets a thing whose `keys.0` names no inbox be its own. (a) Require an inbox thing for grants from outside; (b) keep "else itself". Working: (b) as specified, pending this.
13. **Requirements wording**: spec/requirements.md says the grantee learns where a thing is "from the grant's notice"; that is the grant signal, while the spec's Notice is a role commit sealed to a holder on a connection (notes/terms.md, Tells). Also owed there: the stub as a concept beside the sync unit.

How many signals a card holder may fire: issues/resource-limits.md.

## Owed
- **Tests**: a departed stub holder told of its removal (`stubs::a_two_hop_chain_*` asserts only that nothing written since is read); stopped-store ByRole on its own (`grants::a_stopped_sync_holder_catches_up_by_role_*` passes by the resumed member's notice): a store meeting a reader that keeps no record of it.
- **Ignored, cause not sorted**: `differential::a_node_lowered_with_the_public_reads_*` (three; the lowered node keeps the thing unread with no store path), `public::removing_the_public_ends_*`, and the rest `tools/ignores.py "stub rewrite: "` lists (engine 8, osis-sync 18).
- **Full-size differential classes**, the sync ID fork among them: issues/differential-full-size-classes.md.
- An external signal on a dependent thing: issues/behaviour-depends-on-own-keys.md. Each stub one more followed sync ID: issues/many-sync-ids-cost.md.
