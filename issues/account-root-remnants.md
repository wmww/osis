# "Account root" and other removed concepts left in tests and notes
> Summary: The account root, account sides and chain writes are gone (the account is an ordinary thing, spec/permissions.md §8), but test names, helpers and comments and several notes still use them. Source and API docs are clean.
> Priority: low
> Tags: tests, notes

- Tests: "account root" in core/osis/tests/it (api, tracking, making, commits; helper `crate::common::home`, fixture "account root D"), core/engine/tests/it (closure, refs, validity, outside, flows, order), `rotation/tests_members.rs`, core/sync/tests/it (grants, holding, growth, deletes, differential), cli/tests/it/cli.rs; chain writes in engine `flows.rs` (`remover_lists_chain_writes_*`). `rg -i "account root|chain write"`.
- Notes: api-implementation.md (pairing `Unsupported`, account root), chat.md ("the CLI's account root"), sync-access.md, test-properties.md, path-form.md, thing-cost.md, accounts-switch-brief.md ("the tree still reads `keys.0`'s `inbox`"), handoff.md, redesign-plan.md, a2-spec/README.md ("Interim placement until A4", built), account-membership-design.md (mostly history).
- API names: `Write::create_with_keys` and "keys of its own" (the term is "independent"; issues/deprecated-terms.md lists it as gone) and "actor" for a holder thing (`HolderKind::Actor`, `Holder::actor`, `UnknownActor`, `Client::actor`; notes/terms.md has "actor" as a part of a commit): rename or settle the terms (notes/api-design.md, Names carry the meaning).
