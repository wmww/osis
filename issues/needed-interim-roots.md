# Interim roots of what a held thing needs
> Summary: `retention/needed.rs` also keeps a thing this node may read or holds content of (but in the transaction releasing it), because engine integration tests hand peers things they neither hold nor can open; the lib tests hold what they share, the `tests/it` suite (73 tests) and two engine invariant failures remain before the root can go.
> Priority: low
> Tags: engine, tests

The rule (spec/commits.md §5 Forgetting, What a held thing needs) keeps a thing outside the node closure only while a held thing needs it. The interim clause in `rooted` (and `Core::released_now`, `holds_content`, `forget::content`) roots readable things and things whose content a held commit holds.

## Done
- Engine lib tests pass without the clause: a test peer holds what it is shared (`LocalPeer::hold`/`hold_at`, a strong from its node root, notes/node-closure.md Making a thing), grants go through the flow (boxes, so the receiver opens it), observers that judged a thing hold a role on it.
- A thing forgotten whole (`Scope::Whole`) left its `retention^.0` settings in the live index (`apply::validity::forget_setting`, now called wherever a setting part stops being held).

## Left
- Without the clause 73 of `cargo test -p osis-engine --test it` fail (validity 22, order 16, shred 7, waits 6, flows 5, sessions 4, edits 4, setting 3, parts 3, scale, listing, expiry_model). Causes seen:
  - `common::new_thing` makes plain things under the maker's account root and `common::set_edge` writes bare edges: a receiver can never open such a thing (its keys derive from another account's root), so no strong makes it held. Plaintext delivery hid that. These tests need things with own keys granted through the flow (or a node of the maker's account as observer); a strong alone (tried in `new_thing`) and a flow grant inside `set_edge` (tried) clear almost nothing.
  - Role-less observers ("a fresh node", `net(1, 1)` receivers) must become readers or nodes of the maker's account.
  - Things granted properly but never held at the grantee (`flows::lost_setup`): `LocalPeer::hold_at`.
- Engine invariant failures seen only without the clause (likely real, masked by it):
  - `edits::an_original_past_its_keep_frees_its_versions_spec_commits_5`: after a needed drop the live `versions` index keeps a claim the persisted index lacks (`check_index`, "opened from the persisted index").
  - `shred`/`parts` arrival-order tests leave commits pending `MissingChain(author)`: the author's chain went as unneeded before a commit needing it arrived.

Fix: rework the `tests/it` world as above, fix the two invariant failures, then drop `rooted`'s interim clause, `holds_content`, `forget::content` and `Core::released_now`, and check osis, osis-cli, osis-chat and the app tests against main.
