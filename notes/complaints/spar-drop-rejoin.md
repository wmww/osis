# spar-drop-rejoin
> Summary: The brief asked for a world reproducer per drop-rejoin failure class, but every multi-account osis-sync world is ignored while the accounts work lands; found only after reading the harness.

- osis-sync worlds of two or more accounts give no sync IDs (`sync_id_of` is `None`; 169 tests `#[ignore = "accounts: ..."]`), so end-to-end reproducers (purge fall, revocation, stores between) cannot be written now. The pieces were tested at their boundaries instead.
- What would have prevented it: a line in notes/priorities.md (or the brief) saying which harnesses are down during the accounts work, so a brief does not ask for world tests while they cannot run.
