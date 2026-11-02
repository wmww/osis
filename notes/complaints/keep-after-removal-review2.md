# keep-after-removal review 2
> Summary: test-harness footguns met while testing kept copies over the real client port.

- Runtime::Own tests: `sync_now` every 0.5 s starved Bob's passes (status stuck Syncing, the invite never in); every 2 s is fine. A grant right after `import_contact`, before both sides' `wait_synced(All)`, loses the invite about half the time with no diagnostic at the granter: 20 s of nothing, no retry within that window. Worth a look on its own (the same in sim only when `w.run()` hides the timing).
- `net.heal` after `partition`: a node stays unconnected past 15 s (backoff); reopening it is the quick way.
