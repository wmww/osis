# Complaints: review-d2a
> Summary: Snags met reviewing and gating d2-roles.

- A finding whose generator changed with the branch ("not established whether the old rule refused it") is settled fastest by porting its repro test onto main with `tools/bin-at --lib roles-model --patch`, not by comparing searches whose worlds differ.
- osis-perm's `paths_*_agree_large` run in about 2 s (25 CPU-s) despite their `#[ignore]` "large" label: `tools/heavy` is overkill for them; `--short` fits.
- The gate stopped at policy: main (bb6090a00) names issues/addenda-trigger-missed.md in known_failures and priorities, but the file was left untracked in the main checkout; no branch can gate until it lands.
