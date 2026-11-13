# Platforms and input: build the design
> Summary: what remains of notes/app.md (Platforms and input): no selection menu (paste chips stand in for it); a focused field is never brought into view, so with a soft keyboard up it can be hidden.
> Priority: normal
> Tags: app, android

Steps (one branch each; 3 and 4 are independent):
3. Selection menu: kit's model (when, what, where) over `Platform::show_selection_menu` (`Input::selection_menu` asks for one after a long press selects and hides it at the next press; both shells answer no); a tap on the selection opens it too, Android `ActionMode`, kit-drawn elsewhere, secondary click on desktop; the paste chips (`PasteTo`) go.
4. The focused field in view. Nothing asks for it: no widget calls `request_scroll_to`/`request_scroll_to_this` (the scroll-into-view path works: `masonry_core-pan.diff`, `Page`'s `RequestPanToChild`, test `layout::scroll_into_view_shows_it`). Wanted: when the space shrinks under a focused field (keyboard insets, resize) or its caret moves, the page brings the caret's area into view (a text widget asking with its caret rect, or `Ui::set_insets`/`resized` asking for the focused widget). Also: a field that fills (a note's body) takes what the page leaves it, so a short page squeezes it to a sliver (8 px when a keyboard leaves 60 px) and its text clips instead of the page scrolling; it should keep at least its text's height.
