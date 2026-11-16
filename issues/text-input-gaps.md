# Text input and selection gaps in kit
> Summary: Platform text features kit lacks: carets rounded to grapheme clusters (an IME edit inside a cluster jumps back), desktop IMEs without surrounding text or content hints (winit 0.30), Android floating menus without PROCESS_TEXT items, and read-only text that cannot be selected or copied.
> Priority: low
> Tags: app, android

## An input method's caret inside a grapheme cluster moves to its start
`TextArea` sets an edit's selection through Parley's `select_byte_range`, which moves a caret inside a grapheme cluster to the cluster's start. When an input-method edit leaves the caret there (a combining mark or virama typed before text it joins, a setSelection between a letter and its mark), the caret jumps back, and the next typing lands before the cluster. `ime::Sync` compares with the state before the edit, so when the rounded caret equals the old one the keyboard is not told.

Seen by review, not on a device: Gboard's Latin layouts commit whole characters after the caret's cluster. Indic layouts typing a conjunct before existing text, and keyboards sending lone combining marks, would hit it.

Direction: carets at any char boundary in `TextArea` (Parley's `Cursor` is cluster-based, so this is a patch to how the selection is kept, or to the edit model's promise: "the selection afterwards is rounded to clusters", with `Sync` telling the keyboard whenever the selection is not the one the edit asked for).

## Desktop input methods get no surrounding text or hints
On desktop the text input model (notes/app.md, Text input) reaches the platform through winit 0.30, which carries only preedit and commit: no surrounding text, no delete-around-cursor, no content hints. Wayland's text-input-v3 (squeekboard and other on-screen keyboards, through the compositor's input-method-v2) has all three; macOS's NSTextInputClient and Windows' TSF read the text on demand. Context-dependent features (autocorrect, prediction, smart punctuation) are weak there, and every field gets the default layout.

The model is ready: a shell reads `RenderRoot::focused_ime_text` and sends `TextEdit`s; `ime::Sync` tells a keyboard that keeps a copy of the text (Wayland's surrounding text) what changed. What is missing is the platform side: a winit patch (or a newer winit) forwarding `set_surrounding_text`, `delete_surrounding_text` and `set_content_type` on Wayland, then a desktop shell part like osis-android's input connection. Untested on any desktop on-screen keyboard so far.

## Android selection menu lacks other apps' text actions
On a plain View the floating `ActionMode` gets no `PROCESS_TEXT` items (Translate, other apps), which TextView adds itself; osis-android would add them.

Wanted (as TextView's `Editor` does): when the menu opens with a selection, query `PackageManager.queryIntentActivities(new Intent(ACTION_PROCESS_TEXT).setType("text/plain"), 0)` (needs a `<queries>` entry for that intent in the manifest), add one item per activity (its sync ID, after kit's items, `SHOW_AS_ACTION_IF_ROOM`), and on a click start it with `EXTRA_PROCESS_TEXT` (the selected text, which the view would read from Rust) and `EXTRA_PROCESS_TEXT_READONLY` for read-only text. For an editable field, start it for a result and replace the selection with `EXTRA_PROCESS_TEXT` from the result, only if the field, its text revision and selection are still those it was started for (the activity is in front meanwhile; a merge may change the text): a `Ui` entry taking the text and the menu's (field, revision, selection), common code, not a paste. Not checkable on the stock emulator image: its one handler (TalkBack's Select to Speak) returns no text.

## Read-only text cannot be selected or copied
kit's read-only text (`widgets::style::prose`: chat messages, lines) is masonry's immutable `TextArea`, which takes no focus; it paints a selection only when focused, so a mouse drag or long press selects nothing visible, Ctrl+C never reaches it and it gets no selection menu (which acts on the focused field).

Wanted: read-only text selectable by mouse drag and long press, with handles and a menu holding Copy and Select all (the menu model has no editability test yet: it reads the focused `ImeText`, which only editable text has). Needs masonry's read-only text to hold a selection without taking the keyboard's focus from a field (or a focus that is not an input-method session), and `Input` to find the text under a long press rather than the focused field.
