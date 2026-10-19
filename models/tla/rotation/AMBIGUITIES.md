# Rotation model: ambiguities and findings
> Summary: Places where spec/crypto.md §4–§5, spec/sync.md §2/§5 and spec/permissions.md §3–§4 left a choice or failed a checked property, with the assumption the model made. R1 and R2 are TLC counterexamples.

## R1. Re-seal races a removal: a removed member opens the post-removal epoch (TLC: `MC_reorder.cfg`, NoLeak and DepartedLocked fail)
- Text: permissions §3 "A node that may rotate r SHOULD re-seal a current member of r that it sees without a box at a current epoch of r, or whose heartbeat reports it stranded"; crypto §4 "An epoch of role r **covers** a departure of M if it holds no box for M"; permissions §3 "A node that removes a member ... MUST, in the same sync and before any other upload, place the removal ..."; commits §4 has no rule making a rotation wait for the removal it covers.
- Trace (9 states): admin a1 removes m1 and places the removal; a1 rotates to e1 without m1's box, registers it and writes content under e1. Admin a2 downloads the rotation e1 before the removal commit. To a2, m1 is still a current member and has no box at the current epoch e1, so a2 re-seals m1 at e1 by inbox. m1 now holds e1 and reads the content a1 wrote after removing it.
- The missing box that marks a deliberate exclusion looks exactly like the missing box that triggers a re-seal. The same happens through a removed member's stranded heartbeat.
- It needs a2 to get the rotation before the removal. One server's cursor sync keeps log order (`MC_safety.cfg` holds with `InOrder = TRUE`), but range reconciliation, a second server or a member peer gives no order.
- Not reachable through the history box: a2 rotating while unaware would box m1 with e1 in its history, but that rotation is wrapped under e1, which m1 cannot read (checked: without re-seal, NoLeak holds with any order).
- Options: (a) a rotation names the departures it covers (or carries the removal), and a node does not re-seal a member a held rotation omitted until it has a later grant or edge for that member; (b) apply a rotation only after the membership commits its author held (a causal dependency for rotations); (c) re-seal only on a stranded heartbeat whose author's edge the re-sealer has verified at the heartbeat's `ts`. (a) is the smallest.

## R2. A member whose next step's claim set was dropped is never reached (TLC: `MC_drop.cfg`, CurrentOpens fails)
- Text: sync §5 "A claim at a step whose set the server has dropped is refused; such a member is reached only through its inbox"; sync §4 claim sets kept "until it has been superseded for `MEMBERSHIP_KEEP`"; permissions §4 the stranded heartbeat is required only "when it reached the label's head"; permissions §3 re-seal triggers: no box at a current epoch, or a stranded heartbeat.
- Trace (8 states): a2 rotates twice (e1, e2), registers both steps and uploads both rotations. The server drops step 1's claim set. m1 (and admin a1) still hold only e0: the e0 sync key is answered with step 1, the claim at step 1 is refused. They hold boxes at every current epoch, so nobody re-seals them, and they never reach the head, so they place no stranded heartbeat. Nothing sends to their inbox. They stay locked out.
- In real time this is a member offline longer than `MEMBERSHIP_KEEP` across two or more rotations.
- Options: (a) a member that cannot walk to the head places a stranded heartbeat anyway (deposit needs no open), and admins re-seal on it; (b) admins re-seal by inbox every member whose live heartbeat under L is older than the oldest kept claim set (sync §4); (c) the server keeps, for a dropped step, enough to answer with its child (the path walk needs only step keys, not claim sets), and claims are made at the first step with a kept set the member is listed in. (b) uses existing signals only.

## R3. A re-sealed member (or a grantee) cannot read the history box (reading; not checked)
- Text: crypto §4 history box "written once per rotation of r", in `/secrets` of the rotation commit; crypto §5 a rotation commit "is wrapped ... under the newest read epoch e supersedes"; permissions §3 a re-seal writes "a current member's boxes for that role's current epochs, changing nothing else"; crypto §4 "A grant writes the grantee's boxes ... at each of that role's current epochs".
- A member re-sealed because it lacks the predecessor epoch gets the current secret, but the history box sits in the rotation commit wrapped under the predecessor, which it cannot open; so it cannot read content written under older epochs. The same holds for a grantee unless a `/secrets` compaction snapshot under a current epoch carries the history map.
- Model: re-seal gives only the boxed epochs. Checking this needs grants in the model; the instances here box every member at every epoch, so re-seal fires only in R1.
- Options: say that a re-seal or grant also carries (or points to) the history box of each epoch it seals, or that history is read from a `/secrets` snapshot that every rotation re-places under the label.

## R4. "Newer than the head" across a fork (assumed)
- Text: sync §5 "an admin node that holds a verified epoch newer than the one a server's head registers"; crypto §4 newest "ties by lowest nonce".
- An admin holding only the higher-nonce branch of a fork compares against a head epoch it may not hold. Model: compares by (n, nonce) whether held or not, so an admin holding only the losing branch does not re-register. With every member boxed on both branches this is harmless (`MC_fork.cfg` passes); with grants or keysets, a member boxed only on the losing branch would reach the head stranded and rely on the stranded re-seal (unchecked).

## R5. Encrypting under the newest epoch when its secret is not held (assumed)
- Text: crypto §5 "An uploader wraps under the newest read epoch it holds"; crypto §4 "its **newest** is the current one with the greatest n".
- "Newest it holds" may mean newest among held secrets (even superseded) or the newest current epoch, which it may not hold (a rotator that did not know of it boxed nobody new; with grants a member can be unboxed). Model: newest held current epoch, else newest held secret.

## R6. Re-seal is encrypting under? (assumed no)
- Text: crypto §4 "Encrypting under an epoch means: ... sealing or wrapping a box under its secret or a KEM key derived from it".
- A re-seal box carries epoch e's secret sealed to the member's KEM key, not under e. Model: re-seal is not encrypting under e, so the covers rule does not stop R1. If it were meant to be, the rule would need "boxing e's secret to M" to count, which closes R1 for aware nodes only.

## R7. Claim set contents after a re-seal (assumed)
- Text: sync §2 claim set lists "every actor holding its read secret as the registrar knows it: the holders of boxes carrying it".
- A re-seal after registration adds a box holder the claim set lacks; only a step without rotation (a MAY) lists it. The re-sealed member then holds the head's secret and opens by sync key, so this does not block it. Model: claim sets are fixed at registration.
