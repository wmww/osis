# forged-flag
- Sampling one law over 50 `OSIS_CRDT_SEED` values means 50 runs of the whole crdt lib binary filtered to one test (about 2.5 s each, over 2 min in all); a seed-list env var for one test would make this one run.
- The model crates are named `crdt-model`/`held-model`, not `osis-*`: the first `cargo test -p osis-crdt-model` fails to match.
- Review: `git rebase origin/main` merged tools/known_failures.txt without a conflict yet wrongly: it kept the line the branch removed and revived a line main had replaced (a closed issue's). Diff known_failures against main after every rebase.
- Review: `reject_case` in the vectors only checks that decoding fails, so a stale rule passes on an unrelated error (the text-flag "prune" case failed as "not canonical"; three snapshot cases stop at "snapshot arity", issues/vector-snapshot-rejects-vacuous.md).
