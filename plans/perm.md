# Permissions crate: membership timeline, validity, roster snapshots, certificates, purge rights, move resolution
> Summary: Implement spec/permissions.md as pure logic in `osis-perm` over an abstract held set: the joint layer-1 walk with authority classes, drop set and frontiers; layer-2 per-delta validity; roster snapshots, the tenure ledger and epoch starts; effective role and invite queries; certificate chain assembly and verification; purge rights; the move resolution rule. Differential-tested against a refactored models/membership.
> Tags: permissions, security, tests

Crate: `osis-perm`. Depends on: osis-core (and the core-aspect value types; take them from osis-schema if merged, else define the few structs locally and reconcile). Dev-depends on: models/membership. Unblocks: node-core, membership-flows, keys (who may rotate).
Spec: spec/permissions.md §1–§2, §4–§8; spec/commits.md §2–§4 (kinds, pending rules the node applies with these answers); spec/data-model.md §9 (`/members`, `/tenures`). Notes: notes/permissions.md (membership model findings, scenario outcomes, why class attribution, sticky drops), plans/testing.md §1 (model refactor). Spec trumps this plan.

## Deliverables
- Input model (traits the node implements): `HeldSet` giving, per thing, the edge writes held (each: ts, author node, actor, commit ID, target, member, role, until, invite, kind = grant/change/removal/self-removal/invite grant/redemption, frontier?), roster snapshots held (roster edges with `since`, ledger entries), `/created` records (owner), and the node's receipt record for frontiers. Keep perm free of commit header parsing: node adapts.
- Layer 1 (§5.1): one joint walk over all things ordered by (ts, author node, commit ID); authority at a point (admin, effective invite, self-removal right); attribution by class (owner chain, edge admin, invite level); demotion detection (class falls), drop set D with frontier coverage, restart until stable; self-removals never dropped except single-use redemptions attributed to their grant; epoch starts (§6) cut earlier writes; ledger tenures answer pre-snapshot authority; forward-carried ledgers. Output: a `Timeline` with roster(thing, t), effective role(node, thing, t), effective invite, authority class, and the set of dropped writes with reasons (for diagnostics).
- Frontier type and coverage (per (tid, ak, node) counters plus commit-form IDs; inline or link).
- Layer 2 (§5.2): `delta_valid(author actor, thing, ts, dot) -> Valid | Invalid{by demotion}` using the timeline, newest valid explicit demotion below write, ledger tenures with frontiers, re-grant rule; overlapping node-form ranges from one node void both commits (node supplies ranges).
- Roster snapshot production for a thing by an owner-chain author: roster with `since` for write+ edges and the ledger (ended tenures of write+ with frontiers), carrying the previous ledger forward whole (§6).
- Certificates (§4): given a node and the things on its chain, which held commits form its chain certificates (closed under authors, including demotions of those authors, current `/keys`) and node card; verification of a chain from certificates alone (owner links by `/created`, key actor at the top commits to its key).
- Effective role on a thing (§1) through membership edges and owner links; who may write membership-class aspects (§1), who may rotate (§3), purge rights at request time (§8), moving: resolution of a tid held in thing R through `/was` with standing, else `/moved`, else t, bounded hops (§7).
- Incrementality: the spec rebuilds D from scratch when the held set changes; implement that, scoped per connected component of things (mutual membership links components), with caching of per-thing results and invalidation; correctness first, a benchmark for a 10^4-edge history second.

## Steps
- [x] Refactor models/membership into a library whose rule code mirrors spec sections (plans/testing.md §1) exposing `walk(history) -> outcome`, random history generator, scenario list; keep its binary and tests green.
- [ ] Timeline over the abstract held set; differential tests: random histories from the model → equal rosters, equal applied/dropped sets, equal projection agreement, equal effect of roster snapshots; every scenario in notes/permissions.md as a named test (stolen device backdating, mutual removal, two admin paths, chain-and-edge, link finalization, invite power, single-use redemption, sticky drops); add to the model and test the transitive ownership audit (X demoted on N audits its writes on a thing two ownership levels below N, but not where X keeps the class there by another path).
- [ ] Layer 2 validity; frontier coverage; node-form overlap rule; re-grant restores.
- [ ] Roster snapshot production; epoch start selection; ledger carry-forward; compaction-neutrality test (re-snapshot changes nothing, from the model).
- [ ] Certificates assembly/verification; effective role/invite; purge rights; move resolution; incremental evaluation with an equivalence test against from-scratch.

## Done when
Differential suite and scenario tests green; perm has no dependency on commit/crdt; notes/permissions.md gains an "Implementation" section (held-set traits, incrementality, costs). Delete this plan.

## Progress
