# A leaver cannot confirm its removal once the source has rotated
> Summary: A leaver whose removal reached an admin by the admin's own pull: the admin rotates, the leaver's upload answers code 9 and every reopen code 1, so `leaving` and the leaver's secrets stay though the removal arrived. No observable says it arrived; proposed rule: a rotation naming the removal, delivered to the leaver's inbox (a design change).
> Priority: normal
> Tags: sync, node, security

Repro: `repro_leaving_stays_until_a_source_has_the_removal` (core/test/sim/tests/it/no_server.rs).

`drop_left` forgets a leaver's secrets once `placed` holds: an entry of the removal held at a source (spec/permissions.md §3). A leaver that reconnects is also dialed by the admin, who pulls the removal from the leaver's node log and rotates at once (net-role-sync: the removal is a commit of the thing's one sync ID). The leaver's in-flight upload then answers NOT_HEAD, the head moved past every key it holds, its opens are refused, so it never learns the source has the removal: `placed` stays false forever and `LabelStatus::leaving` stays set. Observed: Alice's `holders` no longer list Bob; Bob reads `leaving: true`.

It also hits a leaver that stays connected: in the no-server shape the admin's pull and rotation win the race against the upload, so `osis leave` ends in exit 6 at the timeout; with a host between them the upload lands first.

**Design question: what tells a leaver its removal arrived.** Nothing a leaver can observe today says so:
- **A refusal is no proof.** Codes 1 and 9 answer any rotation the leaver is not in yet; a rotation for another reason gives the same answers until its re-seal arrives, and a hostile host can send them for nothing. `Phase::Failed` as the signal lets it forget before the removal went anywhere.
- **A step without it is no proof.** A step's claim set that omits the leaver also omits a holder Seal left out or a non-contributory DH result, and the refusal of the claim is unsigned.
- **The rotation itself would be proof, and is out of reach.** It is signed by a node that may rotate, its list names the removal (spec/permissions.md §5.5, the witness rule rotations already use), and it is wrapped under the epoch the leaver holds (spec/crypto.md §5). But it sits under a head the leaver can no longer open (not in the claim set): no pass fetches it.

Proposed rule (a design change: not built): a self-removal has arrived when it is placed, or when this node holds a rotation that names it. The missing piece is getting the rotation to the leaver: the node that rotates for a self-removal delivers that commit to the leaver's inbox, as it delivers a grant (one delivery per covered departure), and the leaver's `drop_left` reads it. It costs a delivery per departure and trusts a node that may rotate, as every rotation does. A hostile rotator can only make a leaver forget a group it asked to leave.
