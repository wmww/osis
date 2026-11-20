# root-tables-review
- `PageParams::set_test` returned the old value for a manual restore, so a test had to drop its worlds by hand before restoring; it now returns a guard (bind it before the worlds). A `costs::take` probe needed a page counter: `pages read` (osis-blob `BlobReader`).
