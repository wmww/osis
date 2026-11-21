# owed-tests
- `tools/mutate.py` cannot plant at a site whose text occurs more than once (the driver's three identical `cx.engine.follow()` lines): it took three hand edits, three builds and three copied-binary runs.
- A scale test's small size can sit below the state paging threshold (1 page load at n, 71 at 10n): elements sized so both sizes page.
- Ephemeral bodies do not survive a restart, so a restart case of an ephemeral rule needs a durable aspect; first tried ephemeral and read a confusing missing-leftover failure.
