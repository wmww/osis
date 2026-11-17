# keel-fast-app
> Summary: Mishaps met on the fast-app branch.

- App tests' hand `deliver` worked only while the other account's commits had not yet been released: the first transaction after ingest dropped them (nothing held needed them), so a grant right after `osis_chat::create` failed `UnknownActor` while one before any write passed. Core's and chat's test helpers already held the other account first; the app's copy had drifted. One shared helper per test binary would have kept them alike.
- A test that writes into a thing granted but never accepted fails `NotHeld` naming the granted thing, not the write: reading the error as "the new note is unheld" cost a debugging pass.
