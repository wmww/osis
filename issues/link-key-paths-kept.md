# A path a link key opened stays decided once the key is dropped
> Summary: `paths::open` tries a held link key's epochs (`Core::link_key_epochs`) up a thing's record chain, but `Engine::drop_link_key` / `unfollow_link` (`settle_link_key`, outside a transaction) re-decide nothing, so a split commit entry opened by a link key alone stays decided after the key goes while a fresh load decides it waiting. Untested; found in review.
> Priority: low
> Tags: engine

- What a node decided of paths must be a function of what it holds (apply/paths.rs module doc): arrivals wake `paths::refresh`, records and secrets going run `paths::openers_gone`; link keys are the one opener input with neither.
- Fix shape: dropping a link key in a transaction that runs `openers_gone` on the things whose record chain the key's thing heads (the walk `open` takes), or `open` not reading session-held link keys for paths at all if no held split commit can need them.
