# Who may hard-delete at a blind node
> Summary: Label keys per role (upload for readers, soft retire for writers, hard delete for admins) are proposed in notes/sync.md. Open: whether a writer's purge takes effect at blind nodes at once (writers hold hard delete, backups exposed to every writer and stolen writer device) or only after the grace period (admin-only hard delete, purge delayed at blind nodes). Constraints tension 8. Left open by owner 2026-10-11.
> Tags: sync, security, permissions

Options:
- Admin-only hard delete (agent's recommendation). A writer's purge is a soft retire; the content leaves the blind node at the end of the per-label grace period, or earlier if an admin shortens it. Backups are safe from every non-admin. The deletion constraint then needs a note that purge at blind nodes is delayed by the grace period.
- Writers hard delete. Purge takes effect at once. Any writer, or any stolen writer device, can wipe a backup label.
- Middle: a separate, shorter purge grace for writer-flagged retires. Delays purge by hours rather than weeks, but a vandal can flag everything.

Also open, not blocking: per-uploader pseudonymous keys for mixed-owner labels (would let uploaders retire only their own entries; leaks uploader count), and the grace-period default. Rate limiting soft retires per label stays a heuristic, not a correctness mechanism.
