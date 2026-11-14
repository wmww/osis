# sync-hooks complaints
> Summary: Footguns met while inventorying the engine's old-sync hooks.

- "Callers only in deleted code" is nearly useless alone: the node wraps the engine and osis reaches it only through node sync, so the deprecation probe flags the engine's whole API (open, run, ingest) next to the real hooks. Every item still needs a hand judgement.
- Two names in the plan's start list (`keeper_due`, `destroyed_labeled`) match no item; a plan naming code should grep it first.
- The probe itself is cheap: `#[deprecated]` on every pub item (a 30-line script) plus one `cargo clippy --all-targets --message-format=json` took under a minute on a warm target.
