# reseal_due errs Permission on an actor the node holds a role on
> Summary: `rotation_holds_large_spec_crypto_4` seeds 500107895400, 192411101971 and 192411103095 fail on main: in settle, `reseal_due` on G at a peer whose `role_now` on G is some role returns `Err(Permission { tid: G })`. Not investigated.
> Priority: normal
> Tags: tests, rotation

Replay: `OSIS_ROTATION_START=500107895400 OSIS_ROTATION_SEEDS=1 cargo test -p osis-engine --lib -- --ignored --exact rotation::tests_property::rotation_holds_large_spec_crypto_4` (fails at main a4c482799: three actors, G and one more by peer 0, one by peer 2; X = peer 2 with 24 commits withheld; the error comes after peers 0 and 1 re-sealed G in the first settle round). Find which: a re-seal the node should make but is refused (a holder left without a box), or a candidate `reseal_due` should not try.
