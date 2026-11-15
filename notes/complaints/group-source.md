# group-source
- `Core::sourced_elsewhere` was dropped by every reload (`load_fresh` builds a blank core and carried it not), so a `forget_local` cleared the group sources in the engine: field carry-overs in `load_fresh` are a hand-kept list; a missed one fails silently.
- A cost test whose fresh walk excludes the measured thing passes even with the memo removed: count work with n things on both sides of the change (mutation probe found it).
