# Model-check the liveness-shaped subsystems
> Summary: Add exhaustive model checking (TLA+ with TLC, or stateright where a Rust model fits better) for the subsystems nothing checks today: sync convergence and rotation/claim-step liveness; optionally an independent re-derivation of the membership walk. Written from spec/ alone so the model is a second reading of the spec, not a copy of our own.
> Tags: tests, sync, crypto, permissions

## Why
The two Rust models (models/crdt, models/membership) are random or bounded-exhaustive checks of procedures. Nothing checks the "eventually" properties: every honest node eventually holds a label's required set; a stranded member is eventually re-sealed; no re-upload/delete ping-pong; every current member can open the newest epoch. Exhaustive checking of tiny instances with liveness is what TLC is for, and a fresh agent that must turn spec/ into a state machine finds every ambiguity in the text. The models do not replace the Rust ones (plans/testing.md).

## Method (every target)
- A fresh agent per target, given spec/ and the target's section list only, never notes/ or tools/. Deliverables: the model, a TLC config per instance size, an **assumptions list** (what was abstracted away and why), an **ambiguity list** (every place the spec left a choice; these are the findings), and the TLC results.
- Crypto is access: "holds secret s" is a set membership, boxes are edges in a graph, signatures are author fields. Blobs are opaque IDs with the metadata the rules read.
- Instances: 2–3 nodes, 1 blind server (2 where server state matters), 1–2 labels, 2–3 epochs, a handful of writes; symmetry sets over nodes and things. State constraints bound counters.
- Checked properties stated as invariants plus temporal properties under weak fairness of honest steps; adversarial steps unfair. Each property cites the spec sentence it checks.
- Owner reviews the ambiguity list; spec fixes go through the normal process (significant ones need sign-off). Then the model is updated to the fixed text and rerun. [x] first round reviewed (design escalation); rerun pending (Progress).
- Lives under `models/tla/<target>/` (notes/architecture.md crate map) with a README (how to run TLC headless, instance sizes, run times). CI runs the smallest instance; larger ones by hand or nightly.
- Per target, choose TLA+ or stateright: TLA+ when the value is notation independence and the state is small; stateright when the model is actor-shaped and would be reused as the simulator's oracle (plans/testing.md). Default TLA+ for the two targets below.

## Targets, in order
1. [x] **Sync convergence** (spec/sync.md §5–§7, spec/commits.md §5): `models/tla/sync`. State: per node a held blob set, readable subset, retention class view, compaction snapshots, purge requests, tombstones, timed deletes; per server a blob set with tombstones and deposit budget. Steps: upload, download, deposit, delete (token level), timed delete, compaction, purge, node offline/online, tombstone expiry, server GC. Properties: safety: nothing must-not-hold persists at a reachable server, projections never break the required set for any reader; liveness: every must-hold blob is eventually at every server a member reaches, no infinite upload/delete alternation, a parked body never causes re-upload loops. Adversary: a server that drops or reorders.
2. [x] **Rotation, claim steps, re-seal** (spec/crypto.md §4–§5, spec/sync.md §5, spec/permissions.md §3–§4): `models/tla/rotation`. State: per role epochs and secrets, boxes (sealed and symmetric), `/keys` keysets, history boxes, registration steps per server (tree by prev), claim sets, member offline spans, heartbeats with stranded flag. Steps: rotate (eager or forced before encrypting), departure (removal, demotion, `until`), register step, claim, re-seal, member returns after missing k rotations, `MEMBERSHIP_KEEP` compaction of steps. Properties: safety: a departed member never opens a secret of an epoch created after its departure (covers rule); a writer never encrypts under a superseded epoch after it holds the rotation; liveness: every current member eventually opens every current epoch of its roles and reads the label (through claims or re-seal), under fairness of admins and writers.
3. **Membership walk** (spec/permissions.md §5–§6), optional. models/membership already checks it; the TLA+ version is an independent derivation from prose. Properties: order independence, termination, projection agreement, the expected scenario outcomes in notes/permissions.md stated as tests. Do after 1 and 2, or when the walk text changes next.

## Not targets
The CRDT join (algebraic; proptests at realistic sizes beat exhaustive tiny ones), byte layouts (vectors), performance.

## Done when
Each target's model checks clean at its smallest instance in CI, its ambiguity list is resolved into spec edits or notes, and notes/testing.md records the models, how to run them and what they do not cover. Then delete this plan.

## Progress
- Targets 1 and 2 landed (models/tla/sync, models/tla/rotation). Their first findings (S1–S10, R1–R7) were resolved by spec edits (notes/mvp-progress.md) and both models now follow the edited text. `models/tla/run.sh small|all` runs them; nightly `models` runs `small`. Results per instance in each README. Target 3 not started.
- **Open findings** (owner review; each AMBIGUITIES.md has traces and options):
  - sync S11 (TLC, `mostabs_serve.cfg`): a body past its absolute keep-at-most before it was uploaded is dropped everywhere and nothing asks for a snapshot, so the live write reaches no other member. S12: carrier checks race between deleters with stale views. S13: timed deletes of bodies still holding live writes. S14: a header-only purge rewrite is never must-hold. S15: a node offline past MEMBERSHIP_KEEP never applies a purge.
  - rotation R9 (TLC, `MC_hist.cfg`): a node re-sealed at an epoch before that epoch's rotation commit reaches it (the window between registering a step and uploading its rotation) rotates and puts that secret in its history box, boxed to the removed member. The other instances assume history boxes carry only secrets whose rotation commit was applied. R8: what "a sync pass that fetched everything" is relative to.
  - issues/reseal-triggers.md residue 1 is broader than written: it needs no fork (`MC_reorder.cfg`): a later rotation by a node that knows the removal omits the member without carrying the departure. Residue 2 reproduces (`MC_drop_refresh.cfg`).
- Done when the open findings are settled into spec edits or accepted limits in notes (then rerun and flip the expected failures in run.sh), and target 3 is done or dropped.
