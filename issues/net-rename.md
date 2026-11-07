# Rename: host, label, placed and the other deprecated words
> Summary: Once the concepts are one (issues/net-one-peer.md, issues/net-role-sync.md), put spec, notes and code in the new words: about 6,500 code uses of host and 7,600 of label, plus placed, routing and the role words issues/deprecated-terms.md points here. Words: issues/net-rework.md. Part of issues/net-rework.md.
> Priority: low
> Tags: naming, spec

- **Spec and notes** move to the new words with each concept change, in the job that makes it; this job sweeps what is left: spec/requirements.md Terms (**Host**) and Data a node cannot read ("the labels it opens"); spec/overview.md Conventions; spec/sync.md (about 80 uses of host); spec/permissions.md, spec/wire.md, spec/data-model.md (`host.0^`, `label`, `inbox`), spec/commits.md, spec/crypto.md; notes (about 850 host, 1,150 label).
- **Code**, mechanically, a crate at a time: host and label across core, cli, app, libs and schema; placed (`Placed`, `place`, `placed_with`, `untie_unplaced`, test names); the harness (`World::add_host`, `NetHost`, `Opening.hosts`); osis-proto's `ClientSession` and `ServingSession::port_only` (issues/net-one-peer.md); CLI commands and flags (`serve`, `--admitted`, `--admit own`).
- **Wire names**: domain and kdf strings (`"label sync"`, `"label claim"`, `"osis v1 label open"`, `"osis v1 static claim"`) and record names (`label.0`, `host.0^`) are format, renamed in place like any format (no compatibility before stability), with their test vectors in the same commit.
- **Also here** (the hub's words and the rows of issues/deprecated-terms.md that name this job): **routing**/**routed** for where a call goes (osis `sources.rs`, engine `routed_away`) becomes source; spec rule words where a role is meant (**edge**, **rights**, **demotion**, **revocation**) and one of **part**/**delta**; engine names under the API's (`Written`, `Mutation::expires`, `CommitKind`, `Time` as `WallMs`). Code's `Edge` types are issues/grant-rename-multi-actor.md's, person issues/account-rename.md's.
- Each row of issues/deprecated-terms.md this covers goes when its last use does. "Carrier" stays: retention's word.

Unsure (implementor): one branch per crate to keep merges small, or one sweep while nothing else is in flight.
