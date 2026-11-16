# Custody differential: t epochs the model holds that the engine does not, at large size
> Summary: `rotation::tests_custody`'s t-custody check (P's nodes and R1 hold every t epoch the model does) passes at small size but fails 38 of 2,000 worlds at large size, in two classes: a node of P makes a t rotation boxing no one in P (only R1 and R2), and a node lacks a t rotation the model counts held (never delivered or pending, its epoch reached only through another rotation's history).
> Priority: normal
> Tags: engine, tests

Replay one seed: `OSIS_CUSTODY_START=<seed> OSIS_CUSTODY_SEEDS=1 cargo test -p osis-engine --lib -- --ignored --exact rotation::tests_custody::engine_agrees_with_custody_model_large_spec_permissions_5_4`.

- **No box to P** (most: seeds 676, 683, 1062, 1564, 350, 1208, 252 and the other node-B ones): the t rotation's `secrets.0` holds boxes to R1 and R2 only. The model boxes P at its maker's heads (`TRot::sealed`). Likely the maker's keysets of P are all blocked or unnamed (a head whose height it does not know: spec/crypto.md §4 Seal, "M is left out of r ... re-sealed once it is not"). Open: which side is right, and whether a later re-seal reaches P's other nodes; a t rotation boxing none of its own account's nodes leaves t's writes under it unreadable to them.
- **Rotation not held** (seeds 791, 1288, 1375): the node never held the t rotation commit (not delivered to it, or its only route is another t rotation still pending on its chain, whose history carries the epoch). The model counts the epoch held through that history; a pending commit's history entry does not carry an epoch whose floor the node does not know (spec/crypto.md §4 Carry rule). Likely the model over-claims; check against the spec's carry rule.
