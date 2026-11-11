# covered-label
> Summary: Footguns met while re-checking issues/covered-body-new-label.md.

- `wipe_host` alone does not make nodes re-place anything in `Net`: they keep their cursor-synced view until they reconnect; set them offline around the wipe (as sync_more and tombstone tests do).
- notes/permissions.md still described the pre-history purge sets (five sets, a no-right cover dropping nothing, `abs_timer`); stale notes outside the retention notes are worth a grep after a retention redesign.
