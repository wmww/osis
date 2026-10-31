# receipts-only
- The osis World tests need `w.advance` after `set_online(true)` before anything reconnects (notes/build.md says so for one harness; easy to miss here too): a removal looked unsynced until I advanced.
- osis integration tests are 7-13 s each (World pumping three people plus a pairing); the new one is 13 s. Tier-1 "a few seconds" is not met by this file in general.
- The issue's "applies nothing" missed that a group with secrets of its own seals them only under its own label: found only by the end-to-end test.
