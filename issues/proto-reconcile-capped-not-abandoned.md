# reconcile_differences_capped: the client never abandons
> Summary: osis-proto tier-2 `hostile_peer::reconcile_differences_capped_spec_wire_11_3` fails at once: "abandoned after 2 replies" (the reply queue empties after two replies with no `Refused { kind: Reconcile }`). Fails on 02be71d2e too; deterministic. Either the test's script no longer drives the client to `MAX_RECONCILE_IDS` (it answers the fingerprint ranges, then pops only what was sent) or the cap is gone. Not triaged.
> Tags: proto, security, tests

Repro: `cargo test -p osis-proto --test it -- --ignored --exact hostile_peer::reconcile_differences_capped_spec_wire_11_3` (0.3 s). Found in periodic run 15 (whole tier-2 set). spec/wire.md §11.3; the requirement is no unbounded allocation from a hostile responder, so check which side is wrong before deciding it is only the test.
