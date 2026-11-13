# net-3j complaints
> Summary: what slowed the replacement removal.

- About 90 node test call sites passed a per-group rng seed (`group_seeded`) that only fed the hand rotation; once groups get secrets from the engine the seed is meaningless, so every call changed. A test helper that hand-builds what a flow does drifts from the spec rule (one commit for secrets and sync ID) silently.
- Many node tests built a "plain group with a label" (`create_label` on a group without secrets of its own), a shape the spec forbids; their failures after the rewrite were all about that shape, not about the property they test.
- The heavy lock was held by other runs for about 57 min before this branch's 47 s sweep started.
