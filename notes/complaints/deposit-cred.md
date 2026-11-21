# deposit-cred complaints
> Summary: Workflow notes from removing the never-produced deposit member credential.

- The member record's credential codes are documented nowhere but `opens/records.rs`, and no test round-trips a member row per credential kind, so a renumbering there is checked only by the sims reopening records.
