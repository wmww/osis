# Touch on Android
> Summary: Touch is a mouse to Masonry and kit: a vertical swipe on a card list reorders cards (kit's `VirtualList` drag) instead of scrolling, a drag in a text field selects text instead of scrolling, and there is no touch text selection (long-press a word, handles, a floating toolbar with cut, copy and paste; the paste chips stand in). Pointer events carry `PointerType::Touch` (osis-android's input.rs); nothing reads it.
> Priority: normal
> Tags: app, android

Seen on the emulator (notes/android.md, Open): Cards on home, a swipe up moved People below Tags and recorded an edit ("Edited just now").

Direction, to design first (notes/app.md, The rule: one gesture model for every view, not per list):
- A touch drag scrolls the nearest scrollable (kit's `VirtualList`, Masonry's `Portal`), with fling; reordering takes a long press first, as Android lists do. Desktop touchscreens want the same, so it belongs in kit's widgets keyed on pointer type, not in osis-android.
- In a text field a touch drag scrolls too; a tap places the caret (already), a long press selects the word and shows handles; the selection's toolbar (cut, copy, paste, select all) is a floating `ActionMode` on Android (java/ `startActionMode` with a `Callback2` whose content rect comes from the selection), so the paste chips can go.
- A double tap selects a word today (tap counting in input.rs gives masonry `count` 2), with no handles to adjust it.
