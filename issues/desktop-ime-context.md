# Desktop input methods get no surrounding text or hints
> Summary: On desktop the text input model (notes/app.md, Text input) reaches the platform through winit 0.30, which carries only preedit and commit: no surrounding text, no delete-around-cursor, no content hints. Wayland's text-input-v3 (squeekboard and other on-screen keyboards, through the compositor's input-method-v2) has all three; macOS's NSTextInputClient and Windows' TSF read the text on demand. Context-dependent features (autocorrect, prediction, smart punctuation) are weak there, and every field gets the default layout.
> Priority: low
> Tags: app

The model is ready: a shell reads `RenderRoot::focused_ime_text` and sends `TextEdit`s; `ime::Sync` tells a keyboard that keeps a copy of the text (Wayland's surrounding text) what changed. What is missing is the platform side: a winit patch (or a newer winit) forwarding `set_surrounding_text`, `delete_surrounding_text` and `set_content_type` on Wayland, then a desktop shell part like osis-android's input connection. Untested on any desktop on-screen keyboard so far.
