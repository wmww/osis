# until-roster
- `ManualNet::run` moves the clock up to an hour ahead: a test of a timed event must not call it before it means time to pass.
- A roster test on the granting node passes with the fix removed: its own finalize commit at the `until` tells the roster. Watch from a node that cannot finalize.
- `order::held_set_decides` fails on the base (9f28aade3): `role_sigs` index rebuilt from the commit records differs.
