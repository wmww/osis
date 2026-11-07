# A plausible pending grant can no longer stay pending
> Summary: with parts waiting alone (spec/commits.md §4), a role commit's part on a thing whose record and chain the node holds, signed by an author that may grant there, applies at once unless it is past the drift bound, and then it is not plausible. So `rotation::lost`'s `pending_grants`, `PENDING_GRANT_WAIT_MS`, the armed `l/` due times and the node-sync wake only act in the moment between the clock catching up and the next examination. Probably deletable with the spec sentence in spec/permissions.md §3 that asks for them (a spec change, no Tess sign-off needed before stability).
> Priority: low
> Tags: engine, permissions, spec

One way remains, and it looks unreachable in practice: the part's thing's first admin's `created.0` unknown, with the author holding a grant on the thing. A node that held secrets of the thing from an applied commit held that chain then, and records stay.

What used to keep one pending for good: another part on a thing with no record, or a parked part. Those parts now wait alone and the grant applies. A paged `secrets.0` part with a page away does pend, but neither `authentic` nor `pending_secrets_writes` can read it without its pages, so it is not plausible.

The tests of this path (`flows::aged_out_pending_grant_*`, `sync_review::lost_access_wakes_when_pending_grant_ages_out_*`, `apply::keys::tests::admins_pending_grant_*`, `stale_grant_loses_its_boxes_*`) now hold the state with `Engine::freeze_pending`, a test hook, and a clock trick across a restart. Delete the hook with the machinery.
