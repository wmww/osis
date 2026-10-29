# app-proto complaints
- gui-testing: running `guibox start` in a shell that still has an old session's `env` sourced fails ("compositor did not start", wdotool backend errors): start each session from a clean shell.
- Masonry 0.4 widget tags are never removed with their widget; a rebuilt tagged widget panics in debug ("Tag already exists"). Cost a crash to find; tags are only safe on widgets that live forever.
- Space/Enter press whatever widget holds focus; after a screen rebuild focus can sit on a widget the user never chose, so typing a space "clicked" a tile. The app now focuses the title of a new thing; a general focus policy is still open.
