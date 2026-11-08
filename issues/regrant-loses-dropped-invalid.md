# A re-grant no longer restores what only droppers held
> Summary: with invalid bodies dropped (spec/permissions.md §6), a removed writer's edits that no writer had received by the removal reach nobody who keeps them: other writers drop them at the removal, the author forgets the thing when it loses read (§3), and a copy reaches hosts only if someone uploaded it while valid. spec/requirements.md Permissions ("lost until re-grant") then overpromises: a re-grant restores only what a host or a still-reading author holds. Sim `revocation_carol` (seeds 0 and 2 of 5) fails on it; the gate is red until decided.
> Priority: critical
> Tags: permissions, retention, sync, tess-call

The story: Bob, offline, writes X; Alice removes him not having seen X; Bob writes Y and hands X and Y to Carol directly; both reconnect. Carol applies the removal and drops X and Y in that transaction, before node-sync uploads them; Bob forgets the thing. The re-grant finds no copy. Whether it passes depends on whether an upload beat the removal.

Options: (a) Tess weakens the requirement to "lost; a re-grant restores those a holder still has" and the sim story computes its expectation from who uploaded; (b) a body judged invalid stays until node-sync has placed it at its labels' hosts (it was must-hold when it arrived), then drops; (c) keep invalid bodies held (the old rule). (b) keeps the property at hosts but adds an upload-before-drop dependency between the engine and node-sync.
