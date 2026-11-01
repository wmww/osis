# Epoch establishment: name the departures the rotator knew, drop settled chains
> Summary: Design review after six fix rounds of "settled" establishment (spec/crypto.md §4). Proposal: each rotation's history box names the departure commits its rotator holds (since A's roster epoch start); a node uses an epoch whose secret it holds only once it holds every named commit. No chains, claims lists or fixpoint. Closes the three open establishment issues, needs no requirements change.
> Tags: security, keys, engine, spec

## What R9 / Residue 1 needs
M departed role r of A. A node X that never got the departure commit still lists M as a holder. The leak: X passes along an epoch e that a rotator made *knowing* M had left (e boxes no M, so writers who know treat it as covering). X can do that three ways: (a) re-seal e to M; (b) rotate and box M (X thinks M is a holder) with e in the new history box; (c) grant: harmless (X sees M as a holder already). Channel (b) is the main one and every option has to gate it, so "only re-seal carefully" is not enough.

What we can actually require: before X uses e (encrypts under it, re-seals it, puts it in a history box), X has seen every departure that e's rotator had seen. A malicious valid rotator can always leak what it holds, today too (notes/crypto.md). So "every departure on e's chain" only has to hold for chains of honest rotators.

Why the current rule keeps breaking: it learns about departures second hand. It follows the chain of superseded epochs and trusts each rotator's list of predecessor commits, assuming departures ride in rotation commits. Every link is somebody else's word: a writer's list (writer-rotation-list-skips-removal), a forged valid claim (rotator-lists-forged-claim), a snapshot standing in for a commit (snapshot-keyed-skips-withheld-removal). Invalid links add more (seed 51, pass-through, regrants, injection). The fix is to stop following the chain.

## Option 1 (recommended): named departures, first hand
**Rule.**
- A rotation of r of A to e writes **names** into e's history box plaintext, next to the earlier secrets. Names are A's epoch start (the roster snapshot ID, if any), then every commit the rotator holds, ordered after that start, that departs a holder of A from r. Such a commit applies an edge write on A that lowers a holder below r, or sets an `until` that has now passed, or drops (audits, spec/permissions.md §5.1) an edge write on A giving r. Each name is (thing written on, commit ID, key). The list comes from the rotator's own timeline. It is never copied from a predecessor's names. A commit cannot name itself, so the box also carries `own`, the commit's (`ts`, author node), when the commit itself makes such a departure.
- e is **established** at X when both hold:
  - It is fixed or derived as today; or X holds a valid rotation commit of e; or X holds a valid `secrets.0` compaction snapshot that keys e. The headroom clause stays.
  - If X holds e's secret: some live history entry of (r, e) that opens under that secret has every name held and judged (not pending), or ordered before X's epoch start of the thing it writes on (a dropped grant's demotion may be on A's owner chain: that thing's roster snapshot carries it in its ledger). Its `own`, if present, is met by holding a valid rotation commit of e, or by an epoch start ordered after it.
  - A node without e's secret never boxes or encrypts under e, so it needs only the first part. This keeps today's "stranded until re-sealed" behavior for raced grantees.
- Current, newest and supersession stay as they are (keyset epochs plus history-box epochs), with established meaning the above. The keyset's `supersedes` goes back to a plain set of epochs.
- The re-seal rule's snapshot exception goes ("at an epoch established by a snapshot alone it does not re-seal and MAY rotate instead"). The names, not the rotation commit, are what make a re-seal safe.
- Placement: a rotator uploads the commits it names under each label where it places the rotation (they are A's role commits or certificates, almost always already there).

**Safety (induction).** Suppose X holds e's secret and e is established. Then X holds (or its epoch start covers) every departure e's rotator held. Take any honest rotation f whose secret e's history box carries: e's rotator had f established, so it held f's names; e's names are everything it held, so they include f's. Hence X has seen every departure behind every secret it could pass on. X's own roster then marks M as departed, and its ordinary holder computation never boxes M. Names sit inside the AEAD under e's secret, so only holders of e can write an entry. A forged entry with no names comes from someone who could leak e directly. Against the known attacks:
- writer-rotation-list-skips-removal: owner A rotates to e and names R_s from its own view, whatever W listed. X without R_s does not establish e. W's e1 (and the s its history carries) can still leak, but W held both: accepted.
- rotator-lists-forged-claim: B names its own applied R_s. Missing R_p or the forged claim F plays no part.
- snapshot-keyed-skips-withheld-removal: e names R_s. s keyed by a snapshot has `own`, met only by R_s or a later epoch start.
- Forged valid claim F (writer W while valid): F does not make s established at a node that holds s's secret unless that node meets s's names. Through F, W can leak only epochs it held. A claim F of an epoch W does not hold is harmless: without the secret it boxes nothing.
- Forged invalid claims, injection through re-write dots, regrants: there are no claims or dots to follow.
- Seed 51/243/336 (an invalid rotation behind a valid one): there is no chain, so nothing strands. An invalid commit just makes nothing established.
- Verdict flips: establishment depends only on the held set (the commit's verdict, held names, the epoch start). No fixpoint and no persisted claims, so order independence follows by construction.
- Concurrent forks: each fork names what its own rotator knew. Covers and fork-ending rotations are unchanged.

**Liveness.** An honest rotator names only commits it holds and has uploaded. Names that compaction drops lie before a roster snapshot of the thing they write on, and every syncing node fetches that snapshot. A pending name clears when its certificate arrives. Withholding only delays (as today): meanwhile X keeps its older established epochs and, if it must write, rotates from them. That makes a fork which boxes M; nodes that know of the departure see it does not cover and rotate over it. A junk name stalls only the junk-writer's own epoch, since an unestablished epoch supersedes nothing.

**Cost.** About 80 B per name. A name stays for each departure until the next roster snapshot of A, per rotated role, in every history box a rotation writes (grants and re-seals copy it). For comparison, the history box already grows 32 B per earlier epoch, and boxes cost 1.2 KB per holder. So names stay smaller than the boxes until departures since the last roster snapshot exceed about 15 times the roster. The owner chain's roster snapshot resets the list (policy, not spec). Large lists chunk like any large value.

**Goes away.** spec/crypto.md §4: "settled", the claims list, "a rotation commit of s its list does not name counts for nothing", the invalid-commit-only-toward-settling clause, and snapshot provenance as a separate re-seal class. spec/wire.md §7: `supersedes` becomes a set of epochs. spec/permissions.md §3: the snapshot re-seal exception. In code: `EpochInfo::claims`, `set_claim`, `invalidate`'s claim flips, `settled_claims`, the `fixpoint`, the commit sets in `Superseded`, `newest_is_snapshot`, the Chain/Snapshot split on re-seal, and the `encode_epochs` claims format. The settled differential (core/keys/tests/it/settled.rs) becomes a differential of the predicate.
**Added.** The names in the history box (wire), computing names in the engine from the `Timeline` (applied lowering writes on A after its epoch start, `dropped` points, passed `until`s), the per-epoch predicate, and the placement rule.
**Risk.** The name computation has to be complete: a missed kind of departure means a missed name. Mitigation: build names as a superset ("every commit ordered after the start with a lowering or audit-dropping edge write touching A") and have the differential check that superset. The wire format and persistence change in place (no compat).

## Option 2: departed-holder set (hearsay)
Each history box lists (holder, key of the departing write), again from the rotator's own view. X never boxes a listed holder whose newest edge write X holds is ordered before that key. The safety induction is the same and the size is the same. The gain: no waiting. The losses: a second source of "who departed" next to the role timeline, which every boxing path (rotation box set, re-seal, grant, inbox delivery, claim sets, left-out) has to consult. Re-grants and audit drops need keys compared against writes X may not hold. Entries cannot be checked, so a valid writer can bar any holder from what descends from its epoch. More bug surface than option 1, only to avoid a delay. Rejected.

## Option 3: narrower re-seals only
"Re-seal e only to holders its rotator boxed, or that a later grant names" closes channel (a) only. Channel (b), X's own rotation boxing M with e in history, still needs establishment. Telling a raced grantee (legitimate) from a departed holder needs e to name the grants its rotator knew: O(roster), larger than names. Rejected. Option 1 already drops the snapshot re-seal exception.

## Option 4: writers do not rotate (requirements compromise)
Under today's rule this removes the writer variants (issues 1 and 3), but not the honest-admin snapshot hole, the invalid-link machinery or the chain. Under option 1 it buys nothing for R9: a writer's rotation leaks only what the writer holds. What it would cost the owner: after an `until` expiry or a self-removal, a writer's new content stays readable by the departed holder until an admin rotates (blocking the writer instead would break offline operation). It would also remove the trigger of issues/fork-held-by-non-rotators.md. Not recommended. No compromise is needed.

## Probe (TLA, scratch only, not committed)
I replaced `Est` in core/test/tla/rotation/Rotation.tla with option 1: `nm` = the rotator's known removals plus its own, `Est(x) = {0} ∪ {i ∈ kn[x] : ep[i].nm ⊆ dep[x]}`. Results:
- Pass: MC_live, MC_safety, MC_reorder, MC_fork, MC_grant, MC_plant, MC_drop, MC_fork_reorder (2.61M states). MC_grant_remove was stopped before it finished.
- Negative control (`nm` = own removals only): MC_fork_reorder fails `DepartedLocked` with the Residue 1 trace, but MC_reorder still passes.
- The model never withholds a commit: the wrap order serializes it, and the host holds everything. It has no writers, invalid commits or snapshots. The three open attacks are therefore outside it, and step 4 adds a withholding adversary.

## Suspected separate hole (not yet reproduced)
Holder-actor keysets. Departure M is a device of a person P that holds A: R_P rotates P to P_s and A's admin rotates e, boxing P at P_s. A node X that was withheld R_P rotates A and seals to P's newest keyset *it holds*, P_p. M opens that box. Names on A do not cover departures inside P. Proposed rule: never seal to a holder actor at a keyset epoch older than one named by a box to it at an epoch X has established; leave it out (re-sealed later) until X has that keyset. The same applies to the symmetric form.

## Step plan
0. (small, worker) Engine repro of the holder-actor hole above. If it reproduces, step 3 goes ahead.
1. (worker 1) Spec: rewrite spec/crypto.md §4 establishment as above; spec/wire.md §7 (`supersedes` as an epoch set) and the history-box plaintext (names, `own`); remove the snapshot re-seal exception in spec/permissions.md §3; add the placement rule.
2. (worker 1, same branch) keys and engine. Remove the machinery listed under "Goes away". Add names to the history box and the per-epoch predicate. Compute names in engine rotation from the `Timeline`. Re-point the attack tests (the three issues, seed 51/243/336, regrants, injection, valid forged claim) to assert: not established without R_s, established once it arrives. Replace the settled differential with a predicate differential over random held sets and verdicts.
3. (worker 2, after 0) Keyset floor for holder actors, if reproduced.
4. (worker 2) TLA: names `Est`, a host or peer that withholds a removal commit indefinitely, the negative control as an expected failure; update ASSUMPTIONS/README/AMBIGUITIES.
5. Opus review hunting remnants (claims, settled, snapshot provenance, `Own`). Then the gate plus tier 2: rotation `_large` x5, forks, perm tier 2, sim permission list. Delete the three issues; note the residual (a malicious valid rotator leaks what it holds) in notes/crypto.md.

Orthogonal, unchanged: issues/fork-held-by-non-rotators.md, issues/fork-choice-keys0.md.
