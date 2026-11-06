# App chat: no multi-line messages
> Summary: the app's message box is one line: Enter sends, and Shift+Enter sends too, so Tess's two-line message arrived as two messages. Low priority (Tess). Needs a newline key and a box that grows; `style::input` already takes a `multiline` flag.
> Tags: app, chat

Message box: `chat_input(Input::Text, ...)` in `app/src/ui/chat.rs`, send on `TextAction::Entered`. The log must also show the line breaks a CLI post already carries.
