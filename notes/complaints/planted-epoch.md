# planted-epoch
- First Planted.tla draft (separate Drop action, Budget 2) ran 1.6M states / 10 min at 8 workers: a delivery model with every interleaving blows up fast; dropping covered bodies inside the step that writes or receives the snapshot cut it.
- Started a TLC run outside `tools/heavy` by reflex before remembering the rule; stopped it.
- `body_not_dropped` says nothing for grants (role commits with a `roles.0` part are kept forever): check cover with `Engine::covered` instead.
