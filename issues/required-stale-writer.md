# A writer that has not seen a required retention change loses its write, with nothing to re-send it
> Summary: A write made before the writer's node received a `required.0^` change, with a key after it, turns invalid when the change arrives: read gone everywhere, its own node included. Its node reports `DiagnosticKind::OwnWriteInvalid`; a re-send has no API. A chat message vanishes.
> Tags: engine, api, core-ask

The body stays on the author's node (it received the write first) and goes from others that got it after the setting, and from hosts if a delete-key holder dropped it. The app sees a watch fire and the value gone, and `OwnWriteInvalid` names the commit. notes/api.md says "a client re-sends", which nothing lets it do. The window is one sync gap of the writer (after that its node fills the retention), or for good if the setting is set after members hold the chat: set it at creation.

The read for a re-send exists: `at.history` shows the own invalid entry with its body (`valid: false`; osis-chat `Message::valid`, tested). Left: the app re-sends by writing again, as a new commit: nothing in core does it, and nothing need. Same for a member's writes falling with a kick. Close when an app ships the re-send.
