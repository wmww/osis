# A certificate counts as placed when nothing could wrap it
> Summary: `SyncEngine::certificates` calls `add_cert` even when every `place` returned `None` (no current read secret), and `heartbeat` calls `set_beat` likewise. Once the node has a wrap, the "own copy placed before and gone" check skips that commit for good, apart from its own card.
> Tags: node-sync, permissions

Reachable: `sharing::redeem_link_after_a_rotation_and_a_late_host_spec_permissions_4` and `sync::used_link_with_sharer_offline_spec_permissions_9` reach `place` with a certificate and no wrap (read secrets held, none current). `Core::unboxed_epochs` could enter the same state if a pass ran before the box's entry opened; none did in the `osis` suite. On main too. No failure traced to it yet: look first for a later write whose chain never reaches the label's readers. Way out: `add_cert` and `set_beat` only when something was placed.
