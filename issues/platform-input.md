# Platforms and input: build the design
> Summary: what remains of notes/app.md (Platforms and input): touch is a mouse to Masonry's widgets (a swipe on Cards reorders and records an edit, a drag in a field selects, nothing scrolls by touch, no long press, no selection menu, paste chips stand in for it); a page with a list floors at `MIN_PAGE` and clips its list to a sliver when the keyboard is up.
> Priority: normal
> Tags: app, android

Steps (one branch each, in order; 3 needs 2):
2. Touch gestures in kit (`input::Input`, which already counts taps from the platform's thresholds) and masonry widgets by pointer type: drag scrolls `Portal` and `VirtualList` with fling; long press picks up a row; in text, drag scrolls, long press selects a word with handles. Long press: a timer thread waking the shell's `Waker` after `Thresholds::long_press`.
3. Selection menu: kit's model (when, what, where) over `Platform::show_selection_menu` (the shape is there; both shells answer no), Android `ActionMode`, kit-drawn elsewhere, secondary click on desktop; the paste chips (`PasteTo`) go.
4. The page floor: a page whose content has a list lays out at least `MIN_PAGE` (520 px) tall in a `Portal` (`widgets/limit.rs` `MinHeight`, `render/blocks.rs` `filled`). On a phone with the keyboard up the page gets about 190 px under home's brand, search field and padding, so the `Portal` shows the top of a 520 px page: the list looks collapsed to one card's top (the insets are right: the screen shrinks by exactly the keyboard). With touch scrolling (step 2) it can at least be scrolled; the floor itself is a picked number that fails at both ends, better derived from the content (the list's one row) or the space.
