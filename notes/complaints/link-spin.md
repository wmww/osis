# link-spin
> Summary: Worker complaints from checking issues/link-expiry-spin.md.

- The issue's repro had been fixed by a refactor (577d3afcf) without anyone noticing; bisecting about 750 commits took 10 steps of 1-4 min builds each. A one-line "still reproduces?" check when a big refactor lands near a hang issue would have caught it.
- The row-37 repro asserted on K's grant on the target, which never ends; reading `LinkId::actor` as "the link" is an easy slip.
