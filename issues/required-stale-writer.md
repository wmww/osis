# A writer that has not seen a required retention change loses its write, with nothing to re-send it
> Summary: A write made before the writer's node received a `required.0^` change, with a key after it, turns invalid when the change arrives: read gone everywhere, its own node included. Its node reports `DiagnosticKind::OwnWriteInvalid`; a re-send has no API. A chat message vanishes.
> Tags: engine, api, core-ask

The body stays on the author's node (it received the write first) and goes from others that got it after the setting, and from hosts if a delete-key holder dropped it. The app sees a watch fire and the value gone, and `OwnWriteInvalid` names the commit. notes/api.md says "a client re-sends", which nothing lets it do. The window is one sync gap of the writer (after that its node fills the retention), or for good if the setting is set after members hold the chat: set it at creation.

Left: a read of a thing's own invalid writes for a re-send. Same gap as a member's writes falling with a kick. Not needed before chat lands.
