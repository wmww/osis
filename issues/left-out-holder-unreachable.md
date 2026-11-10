# A holder actor left out by a node gone from it stays cut off
> Summary: a node that leaves holder actor M out of A's rotation (M's keyset blocked by a departure it knows) must later re-seal M, which needs M's next keyset; a node no longer in M learns M's keysets only as M's members place them under A's labels, and left out they hold no current epoch of A to place under. So when A's admin leaves M out while in M and then leaves M (or leaves with another party), M reads nothing new of A for good. The admin's own removal no longer causes this (built); this residual needs a design choice.
> Priority: normal
> Tags: keys, engine, node-sync, tess-call

## Shape
Carol is the one admin of X, shared with team T (T reads X). Carol reads T. Dave is removed from T
by a removal that goes without T's rotation (Seal waiting or Authority failing at the remover), or
Carol and Dave are removed together and Carol hears of it (her inbox notice) before T's new keyset.
Carol still holds T's old secret (she drops it once the loss is judged), knows Dave's departure, so
T's old keyset is blocked at her: her next rotation of X leaves T out (spec/crypto.md §4 Seal).
Once she is no member of T she no longer reads T's label, and T's members, left out of X, hold no
current epoch of X to place T's next keyset under X's labels (chain certificates are wrapped under
the label's newest epoch). Carol never sees T's next keyset, so never re-seals T; nobody else may.
Their stranded notices reach her inbox but carry nothing she can seal to, and a re-seal by inbox
needs T's current deposit seed, which lives in the same `keys.0` she lacks.

Model: `D0_gone_live2` (Depth0, `Follow`: a node follows an actor only while it holds a role on it,
and learns a holder actor's keysets under a target's label only once a reader of both, holding the
target's newest epoch, placed them) fails `CurrentOpens`: c leaves T out of X and never learns T's
next keyset.

## Built: the node's own departure
The common case (Carol alone removed from T, hearing of it before T's new keyset) had the same end:
her own departure blocked T's old keyset at her. A departure of the node itself (its account, its
node) now holds back none of its encrypting (spec/crypto.md §4 Encrypting under): the departed party
is the node, which holds the epoch. Carol then seals T at the newest keyset she holds, T's members
keep X's new epochs and carry T's next keyset to her, whose box is then stale, and she rotates onto
it. Tests: osis-engine `own_removal_from_holder_actor_keeps_sealing_it_spec_crypto_4`; model `D0_gone_live` (passes), `D0_gone_live_secret` (counting the own
departure: fails `CurrentOpens`), `D0_gone` (invariants with d removed too: pass); sim
`team_reads_member_thing` (the earlier per-chat persona shape: counting the own departure it failed
about 2% of seeds, among them 32, 67, 77, 151, 253, 296).

## Options for the residual
- **Carry M's keys to the leaver**: a stranded notice (spec/wire.md §9, spec/permissions.md §4) from
  a holder actor's node carries that actor's current `keys.0` commits (its chain certificates for
  the label). A's admin then learns M's knowing keyset and deposit seed and re-seals M by M's inbox.
  Closes it for any leaver, member or not, and for the issue's earlier sim shapes (refused deposits
  for want of the current seed). Cost: a commit in the notice (about 3.6 KB of `keys.0` per role
  change), the notice judged like a certificate, a wire change.
- **Seal waits at a node gone from M**: instead of leaving M out it makes no rotation of A boxing
  M until M's knowing keyset reaches it (M's members still hold A's epoch, so they carry it).
  Covers the co-departure case only: a node that left M out while a member and then left M is
  still stuck. Its rotations of A (removals from A included, which go alone meanwhile) wait on M's
  rotators.
- **Judge M only while a member** (Depth0 `Judge = "role"`): rejected. `D0_gone_role` fails
  `NoLeakAbove`: c leaves T out for Dave's removal while a member and writes X; gone, it no longer
  judges and re-seals T at the keyset it left T out at, and Dave opens what c wrote knowing his
  removal (the re-seal hole of issues/sealer-cannot-judge-holder.md, by one node).
- **Stated limit**: needs a removal going alone, or two departures heard together before the
  keyset, then the admin leaving the team before it re-seals.

Recommendation: carry M's keys in the stranded notice; it is the channel the left-out holder
already uses, made able to say what it needs.
The same channel would let a node that never read M judge M's keysets by order and leave M out
safely (issues/sealer-cannot-judge-holder.md, Hole 2).
