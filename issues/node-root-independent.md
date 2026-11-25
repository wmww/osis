# Test helpers write the node root beside shared things
> Summary: spec/sync-set.md §1 says the node root is local with no sync ID; the product writes it in commits of its own (the first start, account making in osis-account, `Engine::hold`). The doc-hidden helper `Engine::new_thing` (`hold_where_it_lives`) still writes the root's `holds.0` in the commit minting a thing with admin the node thing, and a commit writing the root beside a thing that is or becomes shared travels with it: its root section is sealed under that thing's sync ID (a `dw/` row of the root nothing lets go), and a receiver, never holding the root's record, judges the commit pending on it (`UnknownCreated` of the root). Fix the helper (the root's strong in a commit of its own, or the tests minting in an account), not the spec.
> Priority: low
> Tags: engine, tests

Ignored on this issue (osis-engine `it`): `closure::waiting_and_pulling_anew_cost_the_thing_not_the_node_closure_spec_commits_5` (no pull anew on entry; not probed further).

A thing minted with admin the node root and made independent is never entered: no own or read thing holds an edge on it, so nothing carries it (spec/sync-set.md §2 First entry). Nothing in the product makes one.
