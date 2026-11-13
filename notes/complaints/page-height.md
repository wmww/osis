# page-height
- guibox `start` fails ("failed to create display") when run from a shell that sourced another session's env (`WAYLAND_DISPLAY`/`SWAYSOCK` inherited): unset them before `start`.
- Checking "each new test fails with the fix disabled" by `git checkout main -- libs/kit/src` pulled in main's newer kit (main had moved past the branch base) and did not build; use the merge base, and `git reset --hard` after (a path checkout leaves files main added).
- Masonry `Flex` with a flex child returns its whole max height, so an unbounded measuring pass panics (`invalid size (w×inf)`); measure at a bounded height.
- Review: Masonry calls a widget's `post_paint` before its children's `paint`, so anything a parent draws from a child's paint-time state is a frame late; pass such state at layout.
- Review: guibox screenshots in the first seconds show an empty window (the app is still loading its store); wait ~4 s before the first shot.
