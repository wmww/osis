# Platforms and input: build the design
> Summary: what remains of notes/app.md (Platforms and input): touch is a mouse to Masonry's widgets (a swipe on Cards reorders and records an edit, a drag in a field selects, nothing scrolls by touch, no long press, no selection menu, paste chips stand in for it).
> Priority: normal
> Tags: app, android

Steps (one branch each, in order; 3 needs 2):
2. Touch gestures in kit (`input::Input`, which already counts taps from the platform's thresholds) and masonry widgets by pointer type: drag scrolls `Page` and `VirtualList` with fling, in the page's one-scroll order (notes/app.md, One scrollable per page: the list defers to its page while what is around it shows); long press picks up a row; in text, drag scrolls, long press selects a word with handles. Long press: a timer thread waking the shell's `Waker` after `Thresholds::long_press`.
3. Selection menu: kit's model (when, what, where) over `Platform::show_selection_menu` (the shape is there; both shells answer no), Android `ActionMode`, kit-drawn elsewhere, secondary click on desktop; the paste chips (`PasteTo`) go.
