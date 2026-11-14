# "Identity only to known actors" forces contortions
> Summary: spec/requirements.md (Offline and network) says a node shows which node, actor or account it is only to nodes of actors it already knows. Sync bends around it in four places, and three of the five sync requirements conflicts come from it. To discuss with Tess: keep, loosen, or design the private mutual recognition it needs.
> Priority: normal
> Tags: sync, security, tess-call

The requirement: "A node shows which node, actor or account it is only to nodes of actors it already knows (it holds their keys). To any other node, a relay, or a node holding data it cannot read, it shows only its address, whoever dialed."

Where sync bends around it (spec/sync-opens.md §2-§3, spec/sync-transport.md):
- **The dialer proves to any key it dials.** Two strangers cannot both wait for the other to prove first, so the dialer proves first to any key it chose to dial: a LAN announcer, a configured address, a dial hint. Anyone who gets dialed (e.g. by answering on a LAN) learns the dialer's identity. Doing it properly needs private mutual recognition, which is not designed (sketch: pairwise DH beacons per known actor, costly at 10^5 known actors; rotating KEM keys).
- **Records found by one-sided knowledge.** The pair record (`r`, Resume) needs both sides to have proved a known actor; when only one side knows the other, the spec reads the rule so the record still counts. A special case, not a principle.
- **A granter proves its account to the grantee's node** (spec/sync-inbox.md §2), so the grantee can tell the inbox re-send is from the granter, before the grantee knows the granter. Proposed requirements wording: "...only to nodes of actors it already knows (it holds their keys), a node it granted access included."
- **LAN rank and fresh keys.** LAN discovery announces a fresh transport key per network join and connections carry a route rank so two connections of one pair can be told apart without identities; one-connection-per-pair needs the peer's proof, which strangers do not give.
- Related limits it leaves: a node keeping S unread shows its filter to every connection (anyone holding S's public values learns it keeps S), and "a node can limit abuse of data it cannot read without learning identities" is already strained (it learns which accounts' nodes open S with it).

The three requirements conflicts it accounts for (issues/sync-tess-calls.md on branch `capstan-sync-rebuild`, Requirements conflicts): identity to a dialed key; a granter proving its account to the grantee; what a sync holder learns (which accounts' nodes open S with it).

Options to discuss:
1. Keep the requirement and design private mutual recognition (cost per known actor, beacon rotation) before release.
2. Loosen it to "a node shows its identity only to nodes it chose to contact or that know it", which matches what is built: dialing is a choice; listeners stay quiet to strangers.
3. Loosen per case with the three proposed wordings in the sync-tess-calls issue.

Built today: option 2's behaviour, reversible (proof order and audiences are per connection, no stored state depends on it).
