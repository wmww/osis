# sync-spec-1c
- The inputs note cites its own lines by number; every inserted line shifts the rest, so its "Covered by" and For Tess numbers drifted by 1-9. Quoting a few words of the cited line would survive edits.
- Item 4's removal signature over `[sync_id, recipient, blob_id]` could not carry the inbox blob's own ID (Blob ID hashes the whole blob, payload included); it binds the commit ID instead.
- The coordinator's model fixes arrived mid-task by message; their traces were in another agent's scratch dir, which was fine to find.
