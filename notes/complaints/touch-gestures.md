# touch-gestures
- A masonry `SizedBox::empty().height(2000)` in a `Flex` column inside a `Portal` lays out only as tall as the window, so a test page built that way cannot scroll; many short boxes work. Cost a debug round.
- The access tree update after the first redraw carries only changed nodes, so a test looking up a label in a later update misses most of the screen; `layout.rs`'s `press` gathers updates.
- The emulator's `adb shell input swipe` is too short and coarse to show a fling on the app's short pages: flings are unit-tested only.
- Review: the start screen (render/start.rs, from page-height's base) built its own `Input` for the failure screen; the rebase only showed it as a compile error, and it would have flung forever there with nothing driving frames. One `Attached` for both now.
- Review: a touch-scroll test over home at 190 px took 6.7 s with 50 px swipes (each pointer event relays out home); 150 px swipes brought it to 2 s.
