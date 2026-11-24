# Entering a thing through a holder, from a bare reference
> Summary: A node whose role on a thing T comes through a holder H (node → H → T) and that holds only a strong to T cannot start syncing T: a reference is a bare tid, and T's own sync ID gives no first box. It enters only with an offer of T, or where something it already syncs carries T. To decide (Tess) before the accounts spec is written: accept that as the rule, or add a way in.
> Priority: normal
> Tags: sync, engine, spec, tess-call

## The case
Alice grants group G write on a document X. Bob is a member of G and holds a strong to X (Alice sent him the reference in a chat). Bob's node knows X's tid and nothing else: not X's sync ID, and no box of X's secrets to G. Holding a holder for keys starts from a thing already synced, so it cannot start here.

It enters X today where one of these holds:
- **An offer**: the grant's fire reached G's inbox and Bob's node syncs G within the time G keeps the signal (90 days by default, and only where G's admins enable grants from outside).
- **A carrier**: G itself references X (X is then in G's sync unit, which Bob's node syncs), or another node of Bob's account already entered X (X is then in his account's unit).
- **The edge piece under the holder**: a node syncing both G and X logs the grant with X's boxes to G and X's sync ID under G's sync ID. This is the last grant list kept with a holder, a function of what nodes hold that decides nothing; it costs every reader of G a copy of each rotation of each thing below G (notes/holder-access-study.md, Baseline).

Otherwise Bob's node holds nothing of X, though his role would let him read it. spec/requirements.md says "the grantee's node syncs it once a strong reference it holds reaches it": true of G, weaker for G's members.

## Options
1. **No new way in.** First entry is by an offer or a carrier; a strong that neither serves shows as not carried. The app's part: taking an offer writes the reference in the holder, so the holder carries what it was granted. Whether the edge piece under the holder then stays (a sibling's and member's shortcut) or goes (no grant list anywhere) is the second half of the call. Needs the requirement's wording weakened for members.
2. **References carry the way in**: the target's sync ID and an entry box per reader holder, as a link key has. Closes the gap; a reference is no bare tid any more, and stale ones need the sync ID's steps.
3. **A search down, for bootstrap only**: from the own actors' key parts to a held strong's tid, judging nothing. Keeps the edge pieces under holders and reads every holder reached.

## Lean (the plan-repair session's, not decided)
Option 1 with the edge piece kept as built: nothing new to build, and options 2 and 3 can be added later without undoing it. The accounts spec needs the answer because a paired node's way into what its account holds roles on rests on the same rule (notes/accounts-switch-brief.md, Does a new device then need no per-holder records).
