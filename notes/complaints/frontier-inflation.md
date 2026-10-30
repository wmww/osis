# frontier-inflation
- Fresh `LocalPeer` peers in node tests do not sync a thing unless `set_syncing` is called, so a commit missing a part applies at once there: a test meant to exercise atomic-apply waits passed for the wrong reason until I added `set_syncing`.
- Review: exhaustive order 40 seeds took 307 s and the gate 251 s at load ~40 (box shared with other agents).
