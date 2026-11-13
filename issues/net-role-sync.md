# Role and sync paired: what is left
> Summary: Role and sync are paired (spec/sync.md §2): a commit giving a thing role secrets of its own makes its one sync ID, never replaced. Left: `send_inbox`'s chain for a sender holding no `label.0` of the thing (likely dead), and two design questions (key actors' sync IDs, per-sync-ID cost). Part of issues/net-rework.md.
> Priority: low
> Tags: sync, spec, engine

## Leftover
- `send_inbox`'s chain "for a thing without a label": for a sender holding no `label.0` of the thing. Never taken in the default tests of osis or osis-node (a probe counted zero hits): goes, with the payload's chain field, unless the sim or the oracles show the case.

## Unsure
- (design) **Key actors** (nodes, link keys) have no role secrets of their own, so no sync ID: they hold roles and sync others' sync IDs. A link key starts from its link text (by static entry, spec/sync.md §2 Static entry), a node through its account's secrets or by pairing. How shared-set matches the first (by static entry): issues/net-first-contact.md.
- (design) Costs (issues/net-shared-set.md, Costs; tick: issues/idle-pass-per-label.md): each shared thing now costs a sync ID, its `label.0` and a home-label inbox.
