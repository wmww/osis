# Derived state is recomputed on every read and every pass
> Summary: osis `sources::world_waiting` (3 nodes, one group, one client grant, 27 signed commits) costs about 3.4 G instructions (270-410 ms debug): key epochs are rebuilt from seeds about 5000 times (76k KDFs), signing keys 437 times, signatures checked 508 times, commit validity judged 784 times, 83 arrived commits decoded 1030 times, `labels()` built 1244 times in 113 passes. Nothing derived is kept between calls; 40% of instructions are malloc/free and BTree building. Every node pays this per pass and per API call, not only tests.
> Priority: normal
> Tags: engine, node, performance, tests

Measured at 31bb78f4f, debug profile (lto off), osis `it` `sources::known_stays_here_and_unknown_goes_to_the_node`, which is almost all `world_waiting` setup (core/osis/tests/it/sources.rs). Counts repeat to a few % run to run (thread timing moves the pass count: 111-113).

Where it goes (exclusive instructions, 3365 M in all): malloc/free/memcpy/drop 27%, curve25519 (ed25519, x25519) 20%, BTree 13%, CBOR 7%, blake3 5%, zeroize 4%, `Value` cmp/clone 4%. `SyncEngine::handle` holds 72% inclusive (113 passes, about 21 M each); the test thread's own API calls 24%: `create` 128 M per node (`create_account` 71 M, its first `commit` 34 M, `fresh_engine` 16 M), `add_client` 100 M, `grant` 89 M, `Joining::finish` 74 M, `sync` 68 M, `pair_accept` 48 M.

Calls (whole test) against what the setup needs:
- `Core::epochs` / `chain_epochs` 4974, `ActorEpochs::account` 4927 and `derived` 4772, `Epoch::derive` 29.5k, `key_actor_role_secret` 29.6k, `kdf` 76k: an account's or thing's epochs are a pure function of its seeds and account view (`account_view` is cached by `view_key`; the epochs built from it are not), rebuilt per read. Needed: once per change of those inputs.
- `SigningSecret::from_seed` 437 (an ed25519 base-point multiply each), of it `label_role_key` 286 from `certificates` in each pass, `deposit_key` 48, `KeyActorKeys::from_seed` 47, `host_key` 32. About 10 distinct keys exist.
- `VerifyingKey::verify` 508 for 132 signatures made (27 commit signatures, 56 stamps, the rest seals, opens, proofs): `Shown::verifies` 222 (possession, from `possession::holds` 172 times, in validity judgments), `verify_stamp` 137, commit headers 83, `ServingSession::accept` 53. `VerifyingKey::from_bytes` 986.
- `Judge::part` -> `valid_on` 784; `CommitBlob::decode_as` 1030 for 83 envelopes; `Tx::get_commit` 840; `Engine::get` 3403.
- `SyncEngine::labels` 1244 (about 11 per pass; `retire_replaced` and `certificates` each rebuild it), `compute_labels` 17% inclusive.

Floor: the work the setup needs (27 commit signatures, the stamps, seals and key exchanges, each checked once by each receiver) is roughly 150-300 curve operations at about 0.45 M instructions each (dependencies are opt-level 2), 70-130 M instructions, 20-40 ms CPU over 3 nodes. Removing the recomputation is worth about 5-8x on this setup and likewise on every node; test setup under 10 ms needs more than that (a setup built once and copied per test, `Peer::fork`).

Wanted (notes/coordination.md, Fast by construction): derived key material (epochs, role and signing keys) kept per version of its inputs; a commit's signature and validity judged once, again only when what it was judged on changes; a commit decoded once per arrival; one `labels()` per pass. A counted check: a pass with nothing new derives no key, checks no signature and decodes no commit; and this setup's counts of the above bounded by small multiples of its commits and nodes.

Method:
- Wall per step: `eprintln!` of `Instant` elapsed after each statement of `world_waiting`, `cargo test -p osis --test it -q -- --nocapture <test>`.
- CPU against wall: `/usr/bin/time -f "wall %e user %U"` on the test binary (0.4 s wall, 0.6-0.7 s user: CPU-bound, nothing sleeps).
- Instructions: `tools/icount target/debug/deps/it-<hash> --exact <test>` (perf_event_open counting works; `perf record` sampling is refused on this box even with `-e cpu-clock:u`).
- Profile: `valgrind --tool=callgrind --callgrind-out-file=OUT <binary> -q --test-threads=1 <test>` (about 20 s); `callgrind_annotate --auto=no --threshold=100 OUT` for exclusive cost by function (bucketed by name pattern); `callgrind_annotate --tree=caller --inclusive=yes OUT` for callers with call counts. Call counts per function: sum the `calls=` lines following each `cfn=` in OUT. Inclusive cost of a recursive function (`Decoder::item'2`, `Walk::walk'2`) counts each level again and reads far too high (`Decoder::item'2` shows 50%, all of CBOR is 7% exclusive): use the non-recursive entry (`cbor::decode` 5.6%) or exclusive cost.
