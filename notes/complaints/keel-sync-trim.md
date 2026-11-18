# keel-sync-trim
- `tools/pertest.py` runs each test in its own process, so a cached fixture's saving never shows in its numbers; the whole-binary count needs a before-binary built separately (the `.bins` copy is gone after the run).
- `tools/deprecated_probe.py` lists items used inside the crate's own src among "unused outside src" (221 of them in osis-sync); finding the truly dead ones took a second word-count pass over src.
