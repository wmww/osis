# prose-port-expiry
- `tools/policy.py` doc_refs checks only `file, Section` / `file (Section)` pointers, not `file §N Section`; code comments use the latter heavily (client-port.md, expiry-creation-design.md), so stale ones rot unseen: held-model `spec_fetch.rs:148` cites `expiry-creation-design.md §6 step 6` (no §6), `ASSUMPTIONS.md:21` "spec/ follows with steps 6 and 7".
- `tools/spec_map.py --gaps --uncited` prints nothing on success; easy to mistake for not having run.
