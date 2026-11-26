# Sync decisions waiting on Tess
> Summary: The reversible sync choices built while Tess decides (dial hints published by default; a node keeping S unread shows its filter to every connection), each with what is built and the option.
> Priority: low
> Tags: sync, tess-call

Each is built the reversible way; one decision each.

- **Dial hints** (spec/sync-inbox.md §2, spec/sync-set.md §1, spec/wire.md §10): every node keeps its entry in `dial.0` on each thing its node root's `dial_on` names (an account's node on the account and its profile; `Engine::publish_reach`); links carry the sharer node's relays and configured addresses. Options: which nodes a profile lists; hints off by default (issues/privacy.md).
- **A node keeping S unread shows its filter to every connection** (spec/sync-opens.md §5 Filter; stated limit spec/sync-hostile.md §2): anyone holding S's public values learns it keeps S. A policy limiting whom it syncs with (spec/sync-opens.md §1 Policy) hides it from the rest.
