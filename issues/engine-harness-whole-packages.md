# Engine test harness: whole-commit deliveries and broadcast certificates
> Summary: About 111 `LocalPeer::packages` call sites (and `Engine::package` hand deliveries) still hand commits whole; certificates go to every node; the sim's quiescence oracle asks only that each node holds what senders send it. Each can hide a carried-set bug: content outside the closure waits forever under a `LocalPeer` carrier, a certificate no real route brings can make a test pass, and a sender omitting content is invisible to the oracle that uses the sender's own rule.
> Priority: low
> Tags: engine, tests

## Sites
`LocalPeer::packages(` by file: core/engine/src/rotation/tests.rs 31, tests/it/scale.rs 15, tests/it/shred.rs 9, src/rotation/tests_planted.rs 9, tests_reseal.rs 8, tests_cut.rs 6, tests_carried.rs 6, tests/it/order.rs 3, tests/it/keys.rs 2, src/undo/mod.rs 2, src/apply/tests_steps.rs 2, tests_paged.rs 2, tests_addenda.rs 2, and one each in synthetic, resnapshot, memory, common, apply_order, sync/tests_tickets, rotation/tests_signing (`grep -rn '\.packages(' core`). Each moves to `packages_for`/`packages_of`/`packages_to` unless whole delivery is what it tests (say so at the site).

## Oracles
- Certificates (`Engine::certificate_parts`) go to every node in `packages_under`: deliver instead what `Engine::certificates(t)` gives for the things whose sync IDs the receiver syncs, plus the named routes (contact card, ticket fire, holder's sync ID), so a missing certificate route fails a test.
- core/test/sim `Sim::check_quiescent` defines "holds what it should" by `Engine::sent_parts` at the sender, the rule under test. Add an oracle independent of it: at quiet, every node holds each valid part any node holds on a thing in its node closure (allowing covered and invalid drops as held-model judges them).
