# selection-menu
- masonry's `TextInput` hands its own `CaretColor`/`SelectionColor` to its text area over the area's, so kit's colours set on the area were silently masonry's defaults (a near-white caret on light fields: the real cause of the caret-contrast issue). Set text colours on the `TextInput`.
- The kit test harnesses (gestures.rs, input.rs) each have their own `Screen`; a new test module reusing one needs its fields made `pub(crate)`.
- Regenerating a vendored patch's `.diff` needs the base it was made against (the commit before the patch was introduced); nothing records it, so it comes from `git log` on the diff.
- adb taps on Android's floating toolbar right after a Copy sometimes land on the clipboard overlay instead (a paste looked lost; it was not).
