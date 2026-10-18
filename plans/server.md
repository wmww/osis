# Blind server
> Summary: Implement the blind node of spec/sync.md §4–§9 in `osis-server`: per-label registration path and head, entries with wraps and stamps, deposits and budget, tombstones, log with sequence numbers, timed deletes and expiry, every operation's authorization exactly as specified, cursor sync and reconciliation via the osis-proto server engine, subscriptions push, signal forwarding, blind-to-blind push replication, caps and rate limits, persistence through `Backend`, and the `osis-server` binary.
> Tags: sync, security, tests

Crate: `osis-server` (feature `bin`). Depends on: osis-core, osis-crypto, osis-label, osis-proto, osis-store (`Backend` only), osis-transport. Unblocks: node-sync tests, sim, apps-e2e.
Spec: spec/sync.md §4 (state), §5 (operations and authorization, re-registration, deletion by token), §6 (protocol), §8, §9; spec/requirements.md (Untrusted nodes: what it may learn, never waits on members). Notes: notes/sync.md (why each rule; What a blind node learns; Policy defaults; Limits), notes/ephemeral.md. Spec trumps this plan.

## Deliverables
- `LabelStore` (osis-proto's trait) implemented over `Backend`: per label the step path (genesis → head; claim sets and entry boxes kept until superseded for `MEMBERSHIP_KEEP`, longer by policy), entries (blob ID, wrap or filler, stamp or none, deposited flag, pending deletion time), tombstones with `TOMBSTONE_LIFETIME`, append-only log with sequence numbers (entries added, deletions, registrations), blob bytes stored once across labels and deleted when unreferenced.
- Operations with their exact checks: Open (sync key against head, else newest superseded step on the path → reply that step's child without claim set), Claim (key in step j's set; static entry in the head's set), Register (genesis only if its delete key hashes to the label ID and the label is new; child of head; else reply head; store the claim set only if it hashes), Stamp/Upload (write key of head; refuse bad stamp, expired prefix, tombstoned ID, oversized; replace wrap/stamp on re-upload and clear deposited, rate-limited), Deposit (deposit key; budget per label: `64 + 4 × claim set size` entries and that × 32 KiB bytes minimum; budget freed on stamp/delete/expiry; reply remaining), Delete (delete key; or token: commitment in prefix + signature the level requires; timed: earliest wins; tombstone), Expiry (delete at T, no tombstone), Download/fetch/reconcile/subscribe only on opened labels, Signals accepted under write or deposit key and forwarded to the label's other subscribers, nothing stored.
- Replication: accept pushed stamped entries from any peer (uploads need no open); optional outbound push to configured peers; never pull.
- Policy knobs with defaults from notes/sync.md: storage cap per label, rate limits per connection for deletes, wrap replacements, deposits, signals; refusals never say why beyond the spec's reply codes.
- Metadata hygiene: the server stores no client identity beyond addresses; log entries carry nothing about authors; a test module asserts the "learns only" list (no AKs, tids, authors) by inspecting stored bytes for known plaintexts in a scripted run.
- Persistence and restart; log horizon (oldest sequence kept) with reconciliation fallback for older cursors.
- Binary: config file (listen address, static key path, data dir, limits), logging, graceful shutdown.

## Steps
- [ ] LabelStore over `MemoryBackend`; operations with unit tests per rule (each cites §5); log replay property (state == replay of log).
- [ ] Engine wiring over osis-proto; loopback tests with a scripted client; subscriptions and signals; budget and tombstone behaviour; timed deletes and expiry with a `Clock`.
- [ ] Persistence over the file backend; restart test; replication push.
- [ ] Binary + transport; localhost end-to-end with a scripted client; limits.
- [ ] Negative tests from notes/sync.md Limits (an ex-member's stale sync key gets exactly one step; a reader cannot upload; a token deletes only its own body; deposits over budget refused; tombstoned ID refused).

## Done when
node-sync syncs through it in the simulator and over localhost; every §5 sentence has a test; notes/sync.md "Server" section records defaults and knobs. Delete this plan.

## Progress
