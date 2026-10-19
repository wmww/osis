# A timed delete lost on a cut connection is never re-sent
> Summary: The sync state records a timed delete (keep-at-most bound) as sent when the Delete command is queued; if the connection is cut before the server answers, the delete is lost and never re-sent, so the replaced body stays at the server past its bound (spec/commits.md §5, spec/sync.md §5). Same pattern as issues/sync-inbox-delivery.md (outbox) and the stamp recorded before a promotion is confirmed (issues/sync-deposit-promotion.md).
> Tags: sync, node, retention, tests

- Seen in the simulator: `osis_sim::replay("keep_at_most", 42)` (also 46, 51, 55; regression test `keep_at_most_seed_42`): node 0 sends `Delete { items: [bfd37.. at Some(..)] }` and the link is cut in the same step; the other timed deletes are re-sent on the next connection, this one never is; an hour later the server still holds the replaced body.
- Fix: record a timed delete (and a promotion, an inbox deposit) as done only on the server's OK status, or clear the record when the connection drops with the request outstanding.
