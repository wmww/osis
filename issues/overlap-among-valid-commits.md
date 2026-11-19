# Overlap only among otherwise valid commits: dropped from S3
> Summary: spec/commits.md §4 voids both commits of one session whose counter ranges on an aspect overlap, counting every held commit, so a holder of a key with no standing (a removed or stolen node) voids that key's honest writes. Counting only otherwise valid commits makes a verdict read itself (worlds with no consistent verdict) and leaves a shared dot with no owner; held-model `overlap` shows both. Dropped from S3; the hole stays.
> Priority: low
> Tags: engine, perm

## The rule and the gap
- **Today**: two commits of one session (session form: source = author tid + nonce, spec/crdt.md §2.1) whose ranges on one (thing, aspect) intersect are both invalid, whole (engine also their `created.0`: `apply/validity.rs` checks `void` first). Judged from headers at apply (`apply/atomic.rs` `overlaps`, `apply_verified`), kept in `records::VOID`; a void commit's addenda vouch for nothing (`validity.rs` `vouching`), its purge requests drop nothing (`retention/purge.rs`). Role commits and snapshots are commit form, so never void.
- **Who**: whoever signs as the author: the author itself, a sibling under an account's shared tid, a stolen or removed node. A stranger cannot: the session names the author and the signature binds it.
- **The gap**: a removed node's unlisted write (invalid at R's holders) on counters its pre-theft write used voids the listed write too (notes/account-membership-design.md §2 step 7).

## Why counting only otherwise valid commits fails (core/test/held-model `overlap`, `tests/it/props_overlap.rs`)
- **Validity reads validity.** A void commit's deltas are inputs of other rules: its addenda vouch, its setting is the current one judging external fires, its purge requests can destroy a thing. With overlap judged among otherwise valid commits and those rules reading final verdicts, held-model's `overlap::consistent` finds held sets with no consistent void set:
  - `liar_setting`: admin X writes, in one session-form commit S, a setting enabling external signal E and a fire of E (counters 1..2); its removal lists S; X fires F on E at counters 1..2, holding no write. F is valid iff S's setting is current iff S is not void iff F is not valid.
  - `liar_addenda`: C (X's) counts only by W's addendum E; E (W removed after it) only by D, X's addendum after a re-grant (X removed again, listing D); D shares C's counters. D is void iff C counts iff D counts.
  - Random worlds with addenda or settings in session form reach it too (8 of 2,922 such held sets at 300 seeds, two of them the hand worlds).
  - Well-founded only as a last layer no rule reads (`Overlap::Valid`: a void commit's addenda and setting still count, a carve-out), or with every rule input (`addenda.0`, `retention^.0` deltas, purge requests) moved to commit form: then the one consistent verdict is `Valid`'s on every held set (`no_verdict_reads_itself_without_rule_inputs`, 2,428 held sets at 30 seeds).
- **A shared dot has no owner.** Dots are a write's identity; un-merge attributes a write by its dot (spec/crdt.md §2.4, §4.6). Under the fix H1 (listed) is valid and J (junk) is not, but both claim dot d. Text element at d: by the order of the ranges, J's char joins as H1's or H1's goes as J's; H1's char never reads (`shared_dot_has_no_owner`). With a valid snapshot that carried J's write before its writer held R, the state holds two writes under one dot. Closing it needs dots owned by validity and snapshot copies counted as valid writes in the overlap judgment: more rules, each a special case of a shared dot.
- What did hold under `Valid` (each with its control): a function of the held set in every order (control: a void judged at arrival and kept differs by order); junk moves no other verdict (control `Held`: 79 of 932 junk commits do); honest sessions never overlap; another session's plain writes never move X's verdicts.

## What stays
- A holder of X's key can void every write of X whose session it knows, a thief after removal included; under the shared account tid, any member's.
- A direction, not designed: make reuse impossible rather than judged (a removal ends the signer's sessions it names at their last counters, or session counters are bound to a signed chain), so no dot is claimed twice by a commit any reader keeps.
- notes/account-membership-design.md (§2 step 7, the list of what builds may not rule out, its negative controls) still names the rule as owed.
