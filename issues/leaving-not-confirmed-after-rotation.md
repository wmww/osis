# A leaver cannot confirm its removal once the source has rotated
> Summary: A node that left while apart: the source applies its removal by its own pull and rotates, so the leaver's upload answers code 9 and every reopen code 1; `leaving` and the leaver's secrets stay though the source holds the removal.
> Priority: normal
> Tags: sync, node, security

Repro: `repro_leaving_stays_until_a_source_has_the_removal` (core/test/sim/tests/it/no_server.rs).

`drop_left` forgets a leaver's secrets once `placed` holds: an entry of the removal held at a source (spec/permissions.md §3). A leaver that reconnects is also dialed by the admin, who pulls the removal from the leaver's node log and rotates at once (net-role-sync: the removal is a commit of the thing's one sync ID). The leaver's in-flight upload then answers NOT_HEAD, the head moved past every key it holds, its opens are refused, so it never learns the source has the removal: `placed` stays false forever and `LabelStatus::leaving` stays set. Observed: Alice's `holders` no longer list Bob; Bob reads `leaving: true`.

Design question: what tells a leaver its removal arrived. `Phase::Failed` after a head it can no longer open, as `heard` already treats a refusing source, would end the wait, but a rotation for another reason would then let it forget before the removal went anywhere else.
