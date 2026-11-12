# rotation_holds checks no epoch against a party that departed only below the actor
> Summary: rule 2 of `check` (core/engine/src/rotation/tests_property.rs: epochs made by a rotator that saw the peer depart) triggers only on the peer's departure from the actor itself (`departure`), so a party that reached actor A only through holder actors and left one of them is never checked against A's intermediate epochs. A Seal that ignores stale boxes one level down (the `Walk::Seal` stale check in `rotation::blocked_epoch` removed) passes 1800 large seeds; only `blind_sealer_leaves_out_at_a_stale_box_below_spec_crypto_4` catches it.
> Priority: normal
> Tags: security, tests, rotation

The planted Seal fires in about 4% of seeds, but in each the parties the stale box reaches still hold A directly, so nobody departed opens through it; the generator grants every peer on G directly, so a below-only party exists only on the other actors.

Widening the trigger to "any departure of the peer from an actor it lost the role on" is wrong as is: it counts edge writes on actors where the peer never held that role, and rule 2's other excuses (`handed`, `regained`, `base`) are keyed on departures from the actor itself (seed 1467 fails unplanted that way). A sound version needs the trigger to be the departures that cost the peer its path to A, and the limit at the first epoch on each box chain whose secret the rotator lacks (order rule for departures from that actor, Stale for its boxes): the same walk `blocked_epoch` makes, computed from the history.
