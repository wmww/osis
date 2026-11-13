# Platforms and input: build the design
> Summary: kit and the shells break notes/app.md (Platforms and input): touch is a mouse to Masonry and kit (a swipe on Cards reorders and records an edit, a drag in a field selects, no long press, no selection menu); paste chips and a `platform` module behind `cfg(target_os = "android")` in kit's UI; two clipboards; tap counting and the soft-keyboard rule live in osis-android; the soft keyboard shows on focus alone on desktop (winit `set_ime_allowed`); the rail hides at a picked 760 px and Back follows that number.
> Priority: normal
> Tags: app, android

Steps (one branch each, in order; 1 and 4 independent):
1. Platform surface: one interface the shells implement (clipboard, soft keyboard, native selection menu, thresholds); tap counting and the keyboard rule in common code; one clipboard path (masonry's cut/copy/paste work on every OS, paste asked of the shell rather than Ctrl+V caught in masonry_winit); a "wants typing on appear" field property in place of `take_keyboard_request`.
2. Touch gestures in kit and masonry widgets by pointer type: drag scrolls `Portal` and `VirtualList` with fling; long press picks up a row; in text, drag scrolls, long press selects a word with handles.
3. Selection menu: kit's model (when, what, where), Android `ActionMode`, kit-drawn elsewhere, secondary click on desktop; the paste chips and `platform` module go.
4. Layout: the rail from the space it and a page need; Back on a page from the rail's absence.

Also seen: on Android the home list collapsed to one card's top when the keyboard opened.
