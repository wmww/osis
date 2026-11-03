# An expiring write gives a snapshot body no death
> Summary: spec/commits.md §5 and spec/crdt.md §4.8: a write dies at T and a body is replaced as its writes die. Only joins report deaths, so a snapshot carrying a write value-less never gets a death at T, and a snapshot with only such writes never reaches its relative keep at most.
> Tags: engine

`hold_valueless` / `make_valueless` (core/engine/src/retention/mod.rs:546, :618) call no `add_death`; `note_deaths`, `note_copies` and `replay_all` date only supersession. The write's own body drops at T regardless, so only snapshots are affected.

Input: w has `expires: T` and at most D after replaced; a snapshot S carries it live, so S takes at most D (§5 Fixed retention). Past T + D, with nothing superseding w, `check_at_most(S)` has no death and no bound: S stays. It holds no value of w (§4.7), so this is retained stamps and other bodies' bounds, not a privacy leak. Traced, not run.

Fix: date T on the held bounded snapshots carrying the write when it expires, and in `replay_all`; or say in §5 that expiry dates only supersession for snapshots.
