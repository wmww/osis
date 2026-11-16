# Unneeded chains linger by arrival order
> Summary: a thing outside the node closure is judged only when a need of it goes, so one that arrives needed by nothing stays until some later need-judgement drops it: what a node shows of it depends on arrival order; held_set_decides and four tests built on it are ignored until this is settled.
> Priority: normal
> Tags: engine, tests, tess-call

`retention/needed.rs` drops a thing outside the node closure when its last need goes (spec/commits.md §5 What a held thing needs). A thing that arrives needed by nothing (another account's root or D, a co-admin's chain the node learned before anything named it, a thing given before the grant that opens it) is never judged on arrival: it stays until a need-judgement reaches it (a commit of its author forgotten, a pending commit leaving, a holder unnamed, a release). Two nodes holding the same commits then show different things (reads of the lingering records and parts), by arrival order alone.

Judging every record as it arrives (`apply::atomic::learn_record` putting the thing in `Core::needs_due`) closes it but breaks how a node learns accounts: an account chain a node took before anything names it (a contact, a peer it will grant) goes at once, so 840 engine tests fail (grants to unknown holders). So the rule needs a root for what a node keeps on purpose (the accounts it knows), or the spec says such chains are kept while some local reason keeps them. Tess's call on which.

Ignored for it (`#[ignore = "unneeded chains linger by arrival order: ..."]`):
- `order::held_set_decides`: reversed orders show another account's root (`created.0`) the in-order node keeps; nodes at an earlier clock differ from held-model on the access the node under test starts with (`Played::reader`, applied at the setup's time).
- `order::a_creation_pruned_under_a_later_delete_is_replaced_spec_commits_5`, `order::settled_writers_fetch_what_their_first_side_dropped_before_compacting`: the same harness; the latter's scripted dispute also changed shape once `NewTop` things are shared (`share_top`: the other peers read them).
- `judgment::chainless_part_order_spec_commits_4`, `judgment::chainless_role_part_order_spec_commits_4`: the vector replay's fresh node (`judgment::replay`) holds nothing, so what it shows depends on whether a judgement fired; the vectors' fresh node needs a defined holding (a strong and read secrets it holds) before these and `judgment_vectors_spec_permissions_5_2` mean something under the rule.

Once settled: un-ignore them; the order harness's node under test should start from its access alone (`Played::reader`) parked at the account's time (`ACCOUNT_AT`), so an earlier clock judges it as it arrives.
