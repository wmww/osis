# Two ways to prove the right to open a sync ID: is by-role needed?
> Summary: Found by reading (with Tess). A side opens S toward a peer on a secret credential (a read secret, a sync proof, an open signature by the step's key) or on J: a proven actor of the peer holding a role by the rosters held here (spec/sync-opens.md §4; the ByRole item: §5). The secret way works at every peer, a node keeping S unread included, and names no one; by-role works only at readers and needs the peer's identity. To check whether by-role can go, leaving one proof.
> Priority: normal
> Tags: sync, tess-call

What by-role appears to be for, and why each may not need it:
- **A first sync before the key is held**: a holder granted a role that has no secret yet. Gone if what tells it of the grant always carries its sealed secret (the invitation redesign, issues/refs-graph-lifetime.md open question 21).
- **Catching up after a missed rotation**: the new secret is inside S. A holder keeping S unread already follows S's steps by the entry boxes of each claim set (spec/sync-ids.md §2, §6; spec/sync-judgement.md §6), with no roster. If a reader can follow the same path, by-role is not needed here.
- **Refusing a departed holder that shows an old secret** (§4 Departed): a removal comes in one commit with its rotation, and the departed holder gets no box of the new step, so the newest step's credential already refuses it.

To verify before removing anything:
- Can a reader follow the step path as a node keeping S unread does, or does that path assume what only such a node has?
- Does anything rest on opening by J itself? Rosters stay in use for whom to dial and whom to wait for on leaving (spec/sync-opens.md §1, spec/sync-set.md §3); that is not proof to open.
- A timing gap by-role may close: a peer that holds a removal before it holds the rotation's step.
- What ByRole's Offer item, the J classes (reader, sync holder, departed, unknown) and the source classes (§4 "A source") become with one proof.

Independent of the reference graph work.
