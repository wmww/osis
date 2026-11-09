# crdt-differential (review)
- `codec::oracle::decode_snapshot` and the real `codec::decode_snapshot` (stream + `Whole`) share names; a fix landed in the oracle first and looked done until `tests_stream` disagreed. The oracle module's name is the only hint.
- The rebase onto main conflicted in notes/testing.md (the held-model line both branches edited).
