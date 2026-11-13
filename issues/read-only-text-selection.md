# Read-only text cannot be selected or copied
> Summary: kit's read-only text (`style::prose`: chat messages, lines) is masonry's `TextArea<false>`, which takes no focus; it paints a selection only when focused, so a mouse drag or long press selects nothing visible, Ctrl+C never reaches it and it gets no selection menu (which acts on the focused field).
> Priority: low
> Tags: app

Wanted: read-only text selectable by mouse drag and long press, with handles and a menu holding Copy and Select all (the menu model has no editability test yet: it reads the focused `ImeText`, which only editable text has). Needs masonry's read-only text to hold a selection without taking the keyboard's focus from a field (or a focus that is not an input-method session), and `Input` to find the text under a long press rather than the focused field. `style::prose`'s doc claims click-then-Ctrl+C works; it does not.
