# Option: grant a role without earlier history
> Summary: Every grant carries the history box, which opens every earlier epoch, so a new holder reads all retained content. Tess wants adding members without revealing history as a core option, not a chain of chats (notes/chat.md Left out, segments). Also useful for documents and folders, which cannot be segmented.
> Priority: normal
> Tags: spec, permissions, keys, crypto, engine
> Queued: after net step 8 (or beside the late net steps when agents are free); design decided below, model check first

History is a separate entry any holder of the old secret may add to a current epoch's history (spec/crypto.md §4, History add), so the option is per holder, not per epoch: a holder granted without history must be left out of the entries its co-holders add, which the add rule does not know about. A first sync (spec/sync.md §6) fetches what does not open last, after everything else; a holder with no old secrets would fetch and hold such bodies for nothing, so this option should stop that: the same stop a node-local cap would be (issues/partial-history-fetch.md).

Sketch from the chat design (unbuilt, traced by reading only): a read rotation at the add whose earlier secrets are sealed per prior holder instead of a shared history box; a new holder's node tolerates entries it cannot open (a link-key bearer already does); every author's chain certificates re-placed under the new epoch (about 11.5 KB per member). Touches history boxes, re-seals, claims, established epochs (spec/crypto.md §4). Check: must-hold and atomic apply at a holder that cannot open old entries, a prior holder's new node, a holder removed and re-added, concurrent adds.

`retention^.0` (spec/commits.md §5 The setting) must reach a history-less holder: its deltas are read like content, so a newcomer that cannot open an earlier epoch's setting does not know it: it shows and keeps history by no setting and fills no expiry or `final` from it. The grant must carry the setting in force or re-seal it.

This is not forward secrecy against a stolen device: that needs erasable per-device keys (notes/chat.md Rejected designs).

## Tess's decisions
- **Per grant, with a default**: a grant may say "without history"; a group or thing default is an aspect, set the way the history retention setting is (spec/commits.md §5 The setting).
- **Two choices only**: a newcomer sees history from when it was granted, or all of it. No admin-chosen start point.
- **Showing history later**: allowed if easy (it is a later grant with history to that holder).
- **Removed and re-added without history**: keeps what it could read before its removal, and must not get what was written between its removal and its re-add.
- **Metadata**: a newcomer may be able to tell that earlier entries exist (counts, sizes, times), but osis exposes none of it by default (no API surfaces entries the holder cannot open, nor counts of them).

## Design (to check in the model before building)
- **A history cut**: a grant without history is a read rotation at the grant whose history box lists no earlier epoch. Prior holders keep their boxes at the earlier epochs (a rotation removes only boxes its history box covers), so they lose nothing; the newcomer is boxed at the new epoch alone.
- **Later grants with history** (and showing history later): the earlier secrets are sealed per grantee (boxes at those epochs), never added to the shared history box of an epoch a history-less holder holds.
- **Re-added without history**: its old boxes still open the epochs before its removal; the removal rotated, so epochs during its absence are not boxed to it and the cut gives none.
- **Also**: a holder skips fetching bodies it cannot open (issues/partial-history-fetch.md); the retention setting in force reaches it (the grant carries or re-seals it); chain certificates re-logged under the new epoch (about 11.5 KB per member).
- **Cost**: per cut, a box per prior holder per role kept instead of removed; grows with cuts, not writes.
- Check in the model: must-hold and atomic apply at a holder that cannot open old entries, a prior holder's new node, removal and re-add, concurrent grants with and without history, a cut racing a rotation.
