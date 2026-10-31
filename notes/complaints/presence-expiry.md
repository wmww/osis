# presence-expiry
- A sed rename of a test helper (`ephemeral_plain_entries` -> a name colliding with the existing `ephemeral_entries`) also caught the old name's callers; renames of test accessors need a grep for the target name first.
- Local ephemeral expiry runs only on the sync engine's ticks (`MIN_WAKE_MS`, 1 s apart), so an osis-level test of a sub-second expiry cannot watch a value lapse; the keep-alive test counts rewrites instead (`KeepAlive::writes`).
