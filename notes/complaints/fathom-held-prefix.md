# fathom-held-prefix
- Planting a fault behind an env var: an `OSIS_*` name fails every test reading the environment (testenv-known.txt); use another prefix.
- Each plant or knob change is a 4-6 min rebuild of osis-engine's `it` at load 20-45; sizing knobs read from a temporary non-`OSIS_` env var let one build try many sizes.
- CPU-s at load 12-45 moved 85-120 for one binary and size; ingest counts (now printed per size) and `tools/icount` are the comparable measure.
