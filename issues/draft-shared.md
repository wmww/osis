# A draft is not always local
> Summary: issues/api-refactor.md Vocabulary calls a draft "local and unsaved", but a thing with no durable write placed in a synced group is shared (`placed.0~`, ephemeral commits carrying its record), may never be meant to be saved (a shared window), and is a draft only as judged per node. Decide what the word covers before the API uses it.
> Tags: engine, sync, api, naming

Prose now says draft for what the spec called an ephemeral thing (spec/data-model.md §1, notes/ephemeral.md). Three places that fits badly:
- **Shared.** Tess's example: two people use a shared ephemeral window while one is offline. It is unsaved, but not local, and nobody intends to save it.
- **Per node.** The definition is "no durable commit holds its record at this node". A thing durable at its author is a draft at a node that has only its ephemeral commits.
- **Code's narrower word.** `Eph::drafts` is only undone saves.

Options: drop "local" from the Vocabulary and accept window-like drafts; or name the shared case separately (no rule differs, so a second word may be a distinction without a difference). Spec rule text on owner chains still says "ephemeral thing" until owner removal (data-model.md §1, commits.md §2, sync.md §9, permissions.md §1, §5.2); drop that synonym then.
