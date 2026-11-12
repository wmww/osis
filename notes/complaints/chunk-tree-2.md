# chunk-tree-2 complaints
- The freed set first stored whole links (keys included); only the `shred::` tests caught that a set holding keys undoes a drop's shredding. Worth a line in any design that keeps links past a drop: keys go at the drop's transaction end.
- `Engine::me()` is not `core.id.tid()`: probes printing one and tests naming nodes by the other cost a misread of which node did what.
- Memory blobs released from a durable `Engine::run` stay held (`tx.blobs.release(b, false)`): node-sync's `delete_blobs` silently did nothing for ephemeral pieces until given the class.
- An ephemeral author's own snapshot keeps carrying a replaced value until its next snapshot; a test expecting every node to let go after another writer's compaction reads as a bug until that rule is found (notes/ephemeral.md).
