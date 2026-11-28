# held_set_decides: the node under test syncs nothing outside G
> Summary: since the local-part log (b6324e053), order's node under test enters the things outside G only by their grants' signals, which it takes only when a case is made (`made`), after `play` computed what it syncs: it is sent nothing of them, and `order::held_set_decides_plain` fails its coverage floor ("Lists seeds ran, but held-model judged no list element reset"). Taking the fires with its access instead (`take_fires(&mut reader, &fires)` after the access loop in `play`) makes its live `secrets` index differ from its store opened afresh (`check_index`) in 11 default order and judgment tests and in this property (`OSIS_ORDER_SEED=59528694876 OSIS_ORDER_LEN=60`).
> Priority: critical
> Tags: engine, tests

The mismatch is the engine's: a signal followed before the thing's record, its boxes then taken (`flows::retake`), against the open's sweep (`flows::reopen_all`), disagree on one actor's epochs. Start by diffing the two `ActorEpochs` the check prints with the fires taken early, fix that, then take the fires with the access.
