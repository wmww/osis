# rebuild-main
- Merging main into sync-rebuild: tests main ported to the rebuild's API compile-fail only at build time (`Pass` SyncState, `Delivery::First`, `osis_node::` paths); grep main's new tests for removed rebuild names before the first build.
- spec_map rejects main's new anchors on the rebuild (rule names must be section text); expect to repoint every anchor a main test brings.
