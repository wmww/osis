# Option: grant a role without earlier history
> Summary: Every grant carries the history box, which opens every earlier epoch, so a new holder reads all retained content. Tess wants adding members without revealing history as a core option, not a chain of chats (notes/chat-designs/e.md Adding without history). Also useful for documents and folders, which cannot be segmented.
> Tags: spec, permissions, keys, crypto, engine

A first sync (spec/sync.md §6) fetches what does not open last, after everything else; a holder with no old secrets would fetch and hold such bodies for nothing, so this option should stop that: the same stop a device-local cap would be (issues/partial-history-fetch.md).

Sketch from the chat design (unbuilt, traced by reading only): a read rotation at the add whose earlier secrets are sealed per prior holder instead of a shared history box; a new holder's node tolerates entries it cannot open (a link-key bearer already does); every author's chain certificates re-placed under the new epoch (about 11.5 KB per member). Touches history boxes, re-seals, claims, established epochs (spec/crypto.md §4). Check: must-hold and atomic apply at a holder that cannot open old entries, a prior holder's new device, a holder removed and re-added, concurrent adds.

`required.0^` (spec/commits.md §5) must reach a history-less holder: its deltas are read like content, so a newcomer that cannot open an earlier epoch's setting does not know it, writes under no rule and sees its deltas invalid at everyone else. The grant must carry the setting in force or re-seal it.

This is not forward secrecy against a stolen device: that needs erasable per-device keys (notes/chat-designs/d.md).
