# App chat: no multi-line messages
> Summary: the app's message box is one line: Enter sends, and Shift+Enter sends too, so Tess's two-line message arrived as two messages. Low priority (Tess). Needs a newline key and a box that grows; `style::input` already takes a `multiline` flag.
> Priority: low
> Tags: app, chat

Message box: the `Block::Composer` fields, rendered in `libs/kit/src/render/blocks.rs` (`composer`); send on Enter through its `send` action (`app/src/facets/log.rs`). The log must also show the line breaks a CLI post already carries.
