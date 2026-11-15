# fathom-logged-again
- `World::lie` set mid-connection: `Liar::heard` takes the first frame it hears as the Hello, so a `Full` lie set on a live connection never tells full; set it before the connection comes up (a restart).
- `Lie::Withhold` loses the hidden entries for good: the peer's cursor passes them, so lifting the lie and reconnecting never lists them again.
- A must-hold body becoming must-hold later while its own entry is kept is hard to reach in a World (a replaced or covered body leaves the own store at once by default retention); the delete-then-must-hold case differs from a restart only across one, since `toward` stays followed while a delete is seen.
