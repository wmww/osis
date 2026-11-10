# A holder actor left out of a rotation can stay cut off for good
> Summary: a rotation of A that leaves holder actor M out (M's keyset is blocked at the rotator) relies on a later re-seal reaching M, but a re-seal reaches M only through M's inbox, which refuses a re-sealer without M's current deposit key, and A's labels, which M's holders cannot open or read. M's holders then never read A's new epoch, and their placements under A wait forever. Seen in sim `chat_join_leave` (main and zero-growth-1). Design question, not yet fixed.
> Priority: normal
> Tags: keys, engine, node-sync

Property violated: a current holder of an actor gets its current epoch (the re-seal invariant in
`rotation::reseal_candidates` assumes a re-seal reaches its holder). The sim shows it as
`copies_waiting` ("certificate copies still wait", a copy waiting for a re-seal that cannot come)
or as `labels` ("label ... not open at host at quiescence": the holder's readers are stranded).

## Mechanism (`chat_join_leave`)
Chat C (A admin, B writer, C' writer) reads each member's persona; persona P' is C''s, C' its only
admin. A removes C' from the chat (removal + chat rotation in one commit).
1. C' learns its removal from the edge-only inbox notice, before the chat's new keyset. P''s epoch
   boxes the chat at a keyset that does not cover that departure, so P''s read is blocked at C'
   (`blocked_epoch`), and C' rotates P', leaving the chat out (Seal: blocked keyset, spec/crypto.md
   §4 Holder actors) and registering P''s label at the new epoch.
2. A and B (the chat's holders) now lack P''s current epoch: the step's claim set does not list the
   chat, so they cannot open P''s label; A's chain certificates for P' (the chat's later `keys.0`)
   wait (`deferred`, unwrapped).
3. Once C' holds the chat's knowing keyset it re-seals the chat on P'. The re-seal goes to the
   chat's inbox (its home label), signed with the chat's deposit key as C' knows it; the head's
   deposit key comes from a newer seed C' never got (the certificate carrying it is the one A
   cannot place), so the host refuses it (seed 1 on the branch: code 9, then moot; seed 32 on
   main: code 1). Under P''s label the re-seal is wrapped under P''s new epoch, which the chat
   lacks, and the label does not admit the chat anyway.
Nothing else re-seals P' (only C' may), so the chat is cut off from P' for good.

Whether the deposit lands is luck: on main at seed 1 B merges the chat's fork with a writer
`keys.0` that keeps the seed C' holds, and C''s deposit is taken; on the branch A merges it,
moving the label's deposit key past C''s. The inbox path for a departed re-sealer works only
through the residual of issues/fresh-deposit-seed-readable-by-departed.md; closing that residual
would make this deterministic.

Seeds 0..300: main (96bd7d180) fails 32, 67, 77, 151, 253, 296; zero-growth-1 the same plus 1.
In each the removed member rotates its persona on a blocked epoch with no departure of its own
and deposits are refused (codes 1, 9): one cause, not the branch's whole-commit relay rule.

## Options (none modeled yet)
- Re-seal reached like a rotation: a commit carrying boxes of a read epoch e is wrapped under the
  newest held epoch e supersedes (spec/crypto.md §5 says "a commit carrying boxes ... (a
  rotation)"; extend it to re-seals), and an admin issues a step (no rotation) once the head's
  read epoch has a box holder its claim set does not list. Needs a way to know who a claim set
  lists (the registrar erases the step key: e.g. the listed tids in `label.0`'s step record);
  costs a step per re-seal (and per read grant, unless limited to re-seals). A holder that missed
  more than one epoch needs the wrap under an epoch it holds, not one step back.
- Seal waits instead of leaving M out while M's keyset is blocked (as it waits for M's merge):
  then M's holders keep A's current epoch and place M's knowing `keys.0` under A's labels, and A's
  rotation boxes M at it. Rejected once for liveness (issues/blocked-walk-stops-at-readers.md,
  `Walk = "wait"`): every rotation of A at that node waits on M's rotators.
- Narrow the block: a departure from M blocks A's epoch only for a party that loses A by it (here
  C' administers P' and loses nothing). Fixes the chat case only; co-departed parties and other
  re-sealers keep the hole.
- Stated limit.

The model (core/test/tla/rotation, `Depth0.tla`) has re-seals "by inbox and under the label" with
no deposit keys or claim lists for holder actors, so it cannot show this; a model change comes
first. Minimal reproducer shape for tier 1 (node level): group M with members a, b, c and own
secrets, reading P (c its only admin); a removes c from M and then rotates M again with a fresh
seed; c gets the removal notice first; assert a reads P's newest epoch at rest.
