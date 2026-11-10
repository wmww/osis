# A leaver cannot confirm its removal once the source has rotated
> Summary: A leaver whose removal reached an admin by the admin's own pull: the admin rotates, its upload answers code 9 and every reopen code 1, so `leaving` and its secrets stay though the removal arrived. The proposed proof (a rotation naming the removal, by inbox) is unreadable to the leaver and its `keys.0` part leaks the fresh deposit seed; options listed, needs a design decision.
> Priority: normal
> Tags: sync, node, security

Repro: `repro_leaving_stays_until_a_source_has_the_removal` (core/test/sim/tests/it/no_server.rs).

`drop_left` forgets a leaver's secrets once `placed` holds: an entry of the removal held at a source (spec/permissions.md §3). A leaver that reconnects is also dialed by the admin, who pulls the removal from the leaver's node log and rotates at once (net-role-sync: the removal is a commit of the thing's one sync ID). The leaver's in-flight upload then answers NOT_HEAD, the head moved past every key it holds, its opens are refused, so it never learns the source has the removal: `placed` stays false forever and `LabelStatus::leaving` stays set. Observed: Alice's `holders` no longer list Bob; Bob reads `leaving: true`.

While `leaving`, the leaver syncs the group, so it keeps dialing its readers (a direct link's sharer too). It also hits a leaver that stays connected: in the no-server shape the admin's pull and rotation win the race against the upload, so `osis leave` ends in exit 6 at the timeout; with a host between them the upload lands first.

**Design question: what tells a leaver its removal arrived.** Nothing a leaver can observe today says so:
- **A refusal is no proof.** Codes 1 and 9 answer any rotation the leaver is not in yet; a rotation for another reason gives the same answers until its re-seal arrives, and a hostile host can send them for nothing. `Phase::Failed` as the signal lets it forget before the removal went anywhere.
- **A step without it is no proof.** A step's claim set that omits the leaver also omits a holder Seal left out or a non-contributory DH result, and the refusal of the claim is unsigned.
- **The rotation's names are out of a leaver's reach.** A key rotation names departures only inside its history box (spec/crypto.md §4, Names), AEAD under the new epoch's secret, which the leaver is not boxed. The signed `keys.0` keyset carries only the names' digest (spec/wire.md §7). spec/permissions.md §5.5's thing lists are an account's epoch rotations, a different list.

**The accepted rule cannot be built as it stands**: "a self-removal has arrived when placed, or when this node holds a rotation naming it", with the rotation delivered to the leaver's inbox.
- With the commit alone a leaver sees a digest and no preimage. The names are every lowering on the actor the rotator holds (`departures::names`), so recomputing them from the leaver's timeline matches only when both hold the same set: sound, but any lowering the leaver lacks leaves it `leaving`.
- Whatever carries the digest must include the `keys.0` part (`Parts::Edge` drops it). An admin's read rotation writes the fresh deposit seed in that same delta (spec/crypto.md §3), and one delta cannot be split (spec/commits.md §1, delta hash), so the copy hands the leaver the seed the rotation refreshes to shut it out.

Options:
1. New `InboxPayload` position holding the names; the leaver checks them against the signed keyset's digest and looks for its removal. No new message type, but a wire change (spec/wire.md §9), and the leaver learns the names of other departures on the actor. Needs 3 or 4 too.
2. Recompute the digest from the leaver's own timeline. No wire change; only works when nothing else was lowered unseen. Needs 3 or 4 too.
3. Write the deposit seed refresh in a commit of its own right after the rotation, so the rotation's `keys.0` holds only keysets.
4. Encrypt the seed in `keys.0` under the new read epoch (a format change).
