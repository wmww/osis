# Restore cannot continue when the head moves under it
> Summary: A head that moves in the moments a fresh node reads the home group strands that restore for good: only a fresh attempt gets through. It fails `Unsynced` at once, which is honest, but it need not fail.
> Tags: node, api

Found by sweeping the point at which another node's removal rotates the home group during `restore` (`restore_fails_when_the_head_moves_under_it_and_a_fresh_attempt_works`): in 5 of 32 points with one saved peer, 6 of 60 with two, the label goes `Stranded` and stays so for at least 900 s of virtual time, with a "waiting for a re-seal" diagnostic. A re-seal has nobody to reach: this node is not on the roster yet.

Admitting the card's key in `rest_tries` (`Some(t) == via`, as `tries` does for a hint) does not help on its own. Not dug further: retrying on a fresh store works, and a restore racing a rotation is rare.

Related: `SyncState::Stranded` is any one saved peer's `Phase::Failed`, so one peer no key opens a group at keeps a restore from `Synced`, while another serves it (spec/requirements.md, Threat model).
