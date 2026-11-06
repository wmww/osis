# Coarser dating for relative keep at least
> Summary: Idea to study: under relative keep at least a late death only keeps a body longer (safe), so dating deaths coarsely (e.g. when this node first holds the write dead) might let most of the snapshot crediting code in `retention/deaths.rs` go (`carriers`, `Parts::carries`, `dies_in`, `note_copies`, `replay_all`). Keep at most 0 after replaced still needs exact first deaths: check what it alone would need.
> Tags: engine, retention

Unverified. First check every user of death dates (relative keep at least, `ROLE_KEEP` for role-class deltas, snapshot bounds, keep at most 0 with its grace, host deletes) and which need exact dates.
