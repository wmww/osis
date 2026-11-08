# A joiner ingests a long role history in quadratic time
> Summary: A node getting 10^4 role commits on one thing one by one spends 110-160 CPU-s (10^3: about 3-11), most of it per-arrival timeline updates and `apply: join` per `roles.0` delta, each growing with the history or roster; evaluating the same timeline anew takes 1.5-2.4 s.
> Priority: low
> Tags: node, permissions, performance

Repro: osis-node `scale::repro_role_history_join_is_linear`: a joiner ingesting 30 and 300 edge writes on one thing re-judges 30 and 1050 commits and writes 19x the store bytes (quadratic).

At 10^4 (readers, 1000 members joining and leaving), of 112 s: `timelines` 85 s (8.5 ms per arrival; 2.2 ms at 10^3), `apply: join` 17 s, state page load and write 15 s. Role history is never compacted (spec/requirements.md Scale, permission history), so every joiner of a busy group pays this. Likely fixes: evaluate once per ingested batch rather than per commit (a fresh joiner has nothing to keep incremental); find what in a `roles.0` join is O(roster) (5566 per-grant joins in one commit took 481 s). The first admin's own edge write also grows: 4.6 ms at 10^3 history, 15-23 ms at 10^4.
