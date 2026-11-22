# A store on a losing sibling step is never moved on
> Summary: Two admins stepping S for one rotation make sibling steps; a store source (a node keeping S unread) whose head is the sibling `head_of` does not pick is never registered past it, so a revoked sync grantee keeps taking S's entries (the write key does not rotate on a sync revocation) and a current one strands once it does. 28 of 50 worlds of a 9-step script. Proposal: a Register carrying the recorded steps from a step on the source's path, taken only deeper than its head.
> Priority: normal
> Tags: sync, security

**Seen**: sync differential `_plain` seed 991936048185 (`node 1 keeps N store entries under thing 0's sync ID, which it does not hold`; the `rate:` line in tools/known_failures.txt). Shrunk script (replay in a scratch test, notes/sync-test-harness.md, Replaying a script), failing 28 of 50 worlds (`OSIS_SYNC_START=1000 OSIS_SYNC_SEEDS=50`):
```
New(2), Run, Strong(1, None, 0), Write(2, 0),
Give(0, 0, Holder::Node(1), Syncs), Revoke(0, 0, Holder::Node(1)), Run,
Give(2, 0, Holder::Node(1), Syncs), Revoke(2, 0, Holder::Node(1)),
```

## What happens
- Nodes 0 and 2 are admins of T (one account); Bob (node 1) accepted T and is granted sync alone, so keeps S unread.
- Node 0's revoke rotates T (sync and deposit keys; the write key stays) and node 0 issues step A (child of genesis). Node 2 gets the rotation before node 0's `sync.0` commit and issues step B for the same epochs (spec/sync-ids.md §6 Steps: any admin, once it holds an established epoch newer than its recorded head). Both are in `sync.0`; `head_of` picks B (equal depth, lowest step ID). Bob was registered A by node 0 and stops (no sync secret of it).
- Node 2 grants sync again at A's (and B's) epoch: Bob's ticket secret derives A's sync key, so he keeps S again at A. Node 2's revoke issues C, child of B. No registrar moves Bob: `inbox::register::plan` finds his head A off the recorded path (`index` None) and sends nothing; a single Register of C or B is refused anyway (spec/sync-ids.md §6 Register: only a child of the head).
- So Bob stays at A for good, taking every entry stamped under the unchanged write key: a revoked sync grantee keeps S's ciphertext and the storage. A store kept on A by a current grant strands once a write rotation lands on B's branch (it can take no entry stamped under the new write key, and no Register reaches it).
- The ticket-word reading earlier noted for this seed was a misdiagnosis: Bob's role by his sync ticket is the spec's (a node keeping T unread follows its own grant by the steps registered with it, spec/sync-judgement.md §6); the differential's model allows him S kept unread, store empty (`stopped`), which Stops would give once a Register reached him.

## The spec gap
spec/sync-ids.md §6 says "sibling steps stand until a step due for another reason lists past them" (notes/sync-access.md: "`sync.0` holds every branch, so any reader can register a source's branch onward"), but no rule moves a source across branches: issuing makes a child of the recorded head only, Register takes only a child of the head, and Moving it registers only steps after the source's step on the recorded path.

## Proposed rule (coordinator's call)
- **Register carries a branch**: the recorded steps after the deepest step the source's path (the path to its head in `sync.0`'s tree) shares with the recorded path, through the next step the registrar would register (each needs-held as now). A store takes it when the first step's `prev` is on its own path, each step verifies under its `prev`'s delete key, and the last is deeper than its head; its path becomes its path to that `prev` plus the steps, its head the last (Stops then judges the new head as any). A child of the head is the one-step case.
- Equal-depth siblings stand (nothing moves a store sideways), and no move goes shallower, so a relay (a removed node included) can neither flip a store between siblings nor take it back.
- Rejected: one child per tip at each step due (branches never merge, so every later step costs one step per tip, growing with every concurrent issue); a single-step sideways Register at equal depth (any relay flips a store between siblings, and each flip to a sibling whose sync key it lacks is a Stops drop and a refetch from the start); deterministic steps so concurrent admins make the same one (the claim set is the issuer's view of the readers).
- Wire: Register's `step` becomes a list (wire changes are free pre-stability). Reproducer: the script above, constructed by hand on a fixture (two admin nodes of one account, a sync grantee of another), failing before.
