# A tied grant's explicit demotion can be starved by role writes
> Summary: an explicit demotion of a dead tied grant (G, T) waits for a complete pass that ended after the last role commit of G or T applied from elsewhere (spec/permissions.md §2), so a role writer who keeps writing role commits on G or T faster than a pass completes delays the removal indefinitely.
> Priority: normal
> Tags: perm, sync, security

Where: spec/permissions.md §2 (the tied-grant bullet: "a complete pass ... that ended after the last role commit of G or T it applied from elsewhere"); engine `Engine::untie_due` (`may_remove` explicit, then `tie_passes_done` over `passes_wanted`). Each role commit on G or T received from elsewhere restarts the wait, so the edge the dead tie should end stays in force while the churn lasts.

Fix direction (Fathom): wait for a pass that began after the demotion's own `ts` (the moment the tie was judged dead), not after the last role commit: later role commits no longer move the bar, and the pass still sees whatever arrived before the demotion was due. Needs the spec bullet rewritten, `passes_wanted`'s `since` for a dead tie's scope taken from that moment, and a test: role commits on G arriving every pass while a tie is dead, the explicit demotion still lands after one pass.
