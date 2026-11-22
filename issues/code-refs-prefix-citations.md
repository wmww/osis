# Code-name check skips test-family citations
> Summary: tools/code_refs.py skips a name beside `*`, so a cited test family (`foo_bar_*`) whose tests were all renamed or deleted passes; checking that some code word starts with the prefix finds 8 such citations on main, each needing its claim re-checked.
> Priority: low
> Tags: tools, tests

`code_refs.py` skips any word beside `*` (a pattern) and any word ending in `_`, so `name_*` is never checked. A `name_*` family (a word ending in `_`, more than 3 long, an inner `_`, followed by `*`) can be checked by a prefix lookup over the sorted code words (`bisect`); the test's case `foo_*` then becomes stale and a `held_*` case fine. Run on main it reports, with no code word of that prefix:
- issues/account-side-shared.md `an_outsider_reads_the_accounts_writes_across_a_node_removal_*`
- issues/removed-device-reads-later-grants.md `keep::a_taken_inbox_*`
- issues/strip-rule-gaps.md `a_delete_key_holder_never_deletes_*`
- notes/addenda.md `scale::addenda_rejudge_cost_*`
- notes/chat.md `flows::kicked_while_offline_*`
- notes/ephemeral.md `dead_expiring_ephemeral_write_covered_before_expiry_*`
- notes/evidence-derivation.md `a_forgotten_way_*`
- notes/evidence-model-findings.md `open16_a_document_holds_two_copies_*`

Each cited test is gone (most with the old sync): the claim it backed is now untested, or covered under another name. Fix each citation (cite the covering test, or move the claim to a tests-owed issue), then land the check so the next family rename fails its branch.

Other blind spots, by design: a word match, not a definition (`crdt_equals_model` passed while only a format string kept it); a CamelCase name with no inner capital (`Payloads`) and plain words are not checked; a name that exists but is not a test (a builder cited as a test) passes.
