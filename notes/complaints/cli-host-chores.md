# cli-host-chores
> Summary: Mishaps met while making `serve` survive a closed stdout, `hosting show` print the address, and `-v` print diagnostics.

- Finding a diagnostic a tier-1 CLI run can trigger took probes: `watch T AK` reads untyped (no `Mismatch` even with a schema); `share-into` of a thing into an unsynced group (`NotSynced`) works.
- Only the `own_host_device_localhost` tier-2 test fails with the closed-stdout fix off (the other one sees no diagnostic after the close); a fix-off probe was the only way to know.
