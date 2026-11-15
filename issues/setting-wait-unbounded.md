# A setting whose body no one holds stops writing for good
> Summary: spec/commits.md §5 Waiting for it: a node holding no valid setting of a thing while a held header lists a valid `retention^.0` part not received writes no content there (`secrets::awaits_setting`, `usable_role` reads `Read`) until a setting arrives. Nothing ends the wait when the part's body exists nowhere reachable: the only holder of the body was reset or lost before passing it on (a chat's maker whose one node goes after a joiner took the record as a certificate), or an admin writes a setting and sends its header only. Every node holding the header then never writes the thing again. Breaks "no unbounded stall" (lacking is waiting, and waiting must end).
> Priority: normal
> Tags: engine, sync, tess-call

Reached by construction: `osis` `edits::a_setting_not_received_yet_is_waited_for_spec_commits_5` with the closing `deliver` left out.

Who writes the input: an admin of the thing (honest, then lost; or hostile, withholding). A removed device's header-only setting counts only until its removal is held (its later commits void), so it stalls only until then.

Directions (none built):
- The wait ends once a complete pass of every sync ID carrying the thing (spec/sync-status.md §1) ended without the part: the node then writes as with no setting, and a setting arriving later is judged as any late setting (§5: it may move bodies in or out of history). Needs sync's pass facts in a write rule.
- The writer adopts the defaults' bound for what it writes meanwhile (no fire, no history) instead of refusing: no wait at all, but a write in a disappearing chat could outlive the setting's expiry.
