# receipts-only
- The osis World tests need `w.advance` after `set_online(true)` before anything reconnects (notes/build.md says so for one harness; easy to miss here too): a removal looked unsynced until I advanced.
- osis integration tests are 7-13 s each (World pumping three people plus a pairing); the new one is 13 s. Tier-1 "a few seconds" is not met by this file in general.
- The issue's "applies nothing" missed that a group with secrets of its own seals them only under its own label: found only by the end-to-end test.
- Reviewer: the branch failed the gate's `spec_map --gaps` (a capitalised "A frontier MUST NOT" no longer matched its case-sensitive RULES substring, and the new §5.3 MUST NOT had no rule); workers should run `python3 tools/spec_map.py --gaps` after spec edits.
