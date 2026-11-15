# fathom-digest-memo
- The brief named `issues/suspect-judge-cost.md` on origin/capstan-sync-rebuild; no ref had it, so the work went from the brief alone (and no suspect-list receiver exists yet on the rebuild: `Engine::state_digest` is what one will call).
- icount over a whole test binary includes the debug memo comparisons at hits 16 and 256 (each a full digest): per-hit cost shows only in the delta between two round counts past 256 (400 vs 800 rounds).
