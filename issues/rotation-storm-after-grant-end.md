# Merges made on partial views fork again
> Summary: A fork-only merge waits for the end of a complete pass of the actor's labels (`pass_end_rotations`), but a pass can complete while another node's fork is still on its way to the peers, so nodes holding different forks still each read as the merger and fork again; sim `member_churn` seed 655826629624 (setup 655826629616) writes 138 role commits on one group where main's upload path wrote 41.
> Priority: normal
> Tags: keys, performance

## State
- Rule: `rotation_due` merges a fork, or withdraws an unsuperseded epoch not current here, only through `pass_end_rotations`, which `Engine::reseal_due` runs at a complete pass's end (with the holder actors below the actor); `ensure_rotated` merges only forks that miss a departure or are blocked. Forks held alike take one merge (`three_forks_take_one_merge_spec_crypto_4`).
- Left: "complete" means every peer's log of the labels read to its end since the last role commit from elsewhere; a fork its maker placed that no peer pulled yet is outside it. In `member_churn` above, four writers' concurrent finalizes after a grant end fork read, write and sync; about 30 merges follow (was 75 rotations and 170 re-seal/history commits with eager merges), the seed passes, slowly: against main the whole run makes 206 commits to 106, 7578 messages to 4038, 800 held checks to 259, and about 5x the CPU (39 to 7.4 CPU-s); a profile shows no hot spot, the cost is the extra role commits' engine work (epoch sets, CRDT state).

- Shape at node a after the run (role commits carrying g's `keys.0` 52, `roles.0` only 8, `secrets.0` only 51; 111 in all, the same with and without rotation-lows' rules): write epochs by n `{8: 5, 9: 4, 10: 3, 11: 4, 12: 3, 13: 3, 14: 2}`, read and sync alike from n 7: the finalizes' fork at n 8 is merged by several mergers at each n in turn, and each round of forks brings its history adds and re-seals (the `secrets.0`-only half).
- Tried: merging a fork only where it matters (pass-end merge also requires an actor above g anchoring g at keysets Seal cannot pass, `seal_keyset` Wait; spec §4 already gives that as the merge's reason). The seed then stops quiescing at step 52: node 1 never completes a pass of g's label (`synced false`, no traffic), cause not traced. Persistent forks touch more than Seal (label passes, re-seals, history adds), so this needs its own design pass.

- Seen as a storm: `member_churn` setup 670640340529, seeds 670640340531, 670640340533, 670640340543 run to the 5000-delivery cutoff at steps 115-119 on main alike, the queue full of g's role commits (`keys.0`, `secrets.0`).

## Question
No rule over the forks a node holds is independent of which it holds. Options: merge only where a fork matters (a holder actor whose anchors fork, Seal), since the merge rule already handles a fork missing a departure; or a deterministic merger over the forks' makers that does not depend on the forks seen (e.g. the lowest maker by tid among those that may rotate), so a node whose view lacks a fork waits for it.
- Also storms: sim `member_churn` setup 313462591648 seed 313462591652, step 111 (5000 deliveries of `keys.0`/`secrets.0` role commits on one group; on main alike).
