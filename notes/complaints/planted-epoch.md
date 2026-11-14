# planted-epoch
- First Planted.tla draft (separate Drop action, Budget 2) ran 1.6M states / 10 min at 8 workers: a delivery model with every interleaving blows up fast; dropping covered bodies inside the step that writes or receives the snapshot cut it.
- Started a TLC run outside `tools/heavy` by reflex before remembering the rule; stopped it.
- `body_not_dropped` says nothing for grants (role commits with a `roles.0` part are kept forever): check cover with `Engine::covered` instead.
- Review: Planted.tla gives each commit one entry, so it could not show that `Absorbed` listed a commit writing both a carried and a left-out record (a node without the body judged it covered); a model checking the code's cover-by-`Absorbed` for unheld bodies would have. `P_keyset` stopped at a different state count on re-run (32,921 vs 83,469): a liveness violation's count depends on search order.
