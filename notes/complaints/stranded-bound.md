# stranded-bound
> Summary: workflow notes from bounding what a stranded report brings.

- The existing stranded tests (osis `team_left_out_*`, osis-node `stranded_message_*`) all passed with no record or `roles.0` delta taken from a report at all: none needed the chain. A test whose report must bring an edge and a record (`stranded_message_brings_the_holders_authority_chain_spec_permissions_4`) is added.
- clippy's MSRV lint (1.88) rejects `BTreeMap::extract_if` though the toolchain is 1.98.
- Review: a role part's `Meta::valid_at` stays true while its edge write is not applied (a removed admin's grant); only `judged_valid` (the timeline) tells. Easy to check the wrong one.
