# page-height
- guibox `start` fails ("failed to create display") when run from a shell that sourced another session's env (`WAYLAND_DISPLAY`/`SWAYSOCK` inherited): unset them before `start`.
- Checking "each new test fails with the fix disabled" by `git checkout main -- libs/kit/src` pulled in main's newer kit (main had moved past the branch base) and did not build; use the merge base, and `git reset --hard` after (a path checkout leaves files main added).
- Masonry `Flex` with a flex child returns its whole max height, so an unbounded measuring pass panics (`invalid size (w×inf)`); measure at a bounded height.
