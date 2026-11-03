# Every sync pass re-decodes every known actor's secrets
> Summary: `rotation::departures::held_actors` reads and schema-decodes `secrets.0` of every actor the node holds epochs of, per call, and each label's pass calls it through `usable_keys`/`uncovered_by`/`ensure_rotated` and `reseal_due`. Measured in an osis-chat of n members: adding a member costs each node about 3 ms × n of CPU (100 ms at n = 36, release), 49% of a whole run inside it.
> Tags: engine, node-sync, performance

Measured: a chat with no messages, members joining one by one (`osis-chat` `scale_small`, cpuprof on all nodes in one process): an add took 0.04 s of world time at 1 member, 3.6 s at 36, so about 100 ms per node; 100 members took over 20 minutes on the sim before the first message. Profile: `held_actors` 49% inclusive, `usable_keys` 41%, `ensure_rotated`/`uncovered_by` 39%, `secrets_value` and its typed decode 28%, `reseal_due` 17%. `secrets.0` of the chat grows 2.7 KB per member, and every person met adds an actor, so one pass is O(actors + boxes).

Below a few dozen members a chat doesn't feel it. It hits every pass, so posts too (a pass per message per label). Also what the sim can reach: the 10^4 messages, 100 members measure did not finish.

Options, not tried: a memo of `held_actors` on `Core`, cleared by `role_changed` as `unrouted` is (the decode is the cost; rollback has to clear it too); or `collect` reading only the actors its walk can reach, which needs `verdicts`' reach pinned down first.
