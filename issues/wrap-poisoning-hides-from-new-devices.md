# A writer can hide a message from new devices by re-uploading a garbage wrap
> Summary: Any writer can re-upload a held blob ID with a garbage wrap and a valid stamp, and the host replaces the wrap (spec/sync.md §5). A node knowing the key ignores it, but a fresh device takes it, cannot unwrap and does not fetch; holders do not repair it, because the host still lists the entry. Found by reading (chat design review), not run.
> Tags: security, sync, host, node-sync

Paths: `core/node/src/sync/inbound.rs` around the known-key check and the fetch decision. First write a repro. Applies to any shared label, not just chat. One shot per message suffices, so the per-entry rate limit does not help. Ideas to check: first wrap for a blob ID wins at a host unless the uploader proves the key; or a device that cannot unwrap asks another holder and the holder repairs.
