# order-gone
> Summary: worker complaints for the order-gone branch.

- A background chain of oracle `cargo test` runs rebuilds from the current sources at each step: editing code while it runs mixes builds across the chain's results. Finish edits first, or stop the chain.
- A `Stamp` names several writes (a map entry's creation and its value write): `holds_stamp` alone over-matched a dead write in a snapshot; cost a round of 5000-seed oracles.
- Reviewer: a single-seed order replay (`OSIS_ORDER_SEED=... --include-ignored`) shrinks before reporting: 135 s per seed at load, three builds (main, worker, review) to locate a pre-existing failure.
