# Merges made on partial views fork again
> Summary: A fork-only merge waits for the end of a complete pass of the actor's labels (`merge_forks`), but a pass can complete while another node's fork is still on its way to the peers, so nodes holding different forks still each read as the merger and fork again; sim `member_churn` seed 655826629624 (setup 655826629616) writes 138 role commits on one group where main's upload path wrote 41.
> Priority: normal
> Tags: keys, performance

## State
- Rule: `rotation_due` merges a fork only through `merge_forks`, which `Engine::reseal_due` runs at a complete pass's end (with the holder actors below the actor); `ensure_rotated` merges only forks that miss a departure (`merge_due`) or are blocked. Forks held alike take one merge (`three_forks_take_one_merge_spec_crypto_4`).
- Left: "complete" means every peer's log of the labels read to its end since the last role commit from elsewhere; a fork its maker placed that no peer pulled yet is outside it. In `member_churn` above, four writers' concurrent finalizes after a grant end fork read, write and sync; about 30 merges follow (was 75 rotations and 170 re-seal/history commits with eager merges), the seed passes, slowly: against main the whole run makes 206 commits to 106, 7578 messages to 4038, 800 held checks to 259, and about 5x the CPU (39 to 7.4 CPU-s); a profile shows no hot spot, the cost is the extra role commits' engine work (epoch sets, CRDT state).

## Question
No rule over the forks a node holds is independent of which it holds. Options: merge only where a fork matters (a holder actor whose anchors fork, Seal), since `merge_due` already handles a fork missing a departure; or a deterministic merger over the forks' makers that does not depend on the forks seen (e.g. the lowest maker by tid among those that may rotate), so a node whose view lacks a fork waits for it.
