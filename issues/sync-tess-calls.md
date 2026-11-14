# Sync decisions waiting on Tess
> Summary: The reversible sync choices built or specified while Tess decides, and three proposed spec/requirements.md wordings (not applied) where the sync spec goes past what requirements allow; each with what is built now and the option.
> Priority: low
> Tags: sync, tess-call

Each is built or specified the reversible way; one decision each.

## Behaviour
- **Last copy on leaving** (spec/sync-set.md §3): removing a thing from every node's synced group drops it from every node of the account once their own commits are held elsewhere, even when no other account holds it, so it can lose the last copy. Option: keep it until another holder's stream showed it whole.
- **Sync-only holders keep no subgroups** (spec/sync-set.md §4): a grant is per sync ID, so a new subgroup is kept only once granted too; an app policy may grant new subgroups.
- **Dial hints** (spec/sync-inbox.md §2, spec/wire.md §10): every node publishes `reach.0` and lists itself in its account profile's `dial^.0` (`osis_engine` `dial::lists_on_profile`); a grant shows the grantee the granting node's dial hint; links and contact cards carry the sharer node's dial hint by default. Options: which nodes a profile lists; hints off by default (issues/privacy.md).
- **Records found by one-sided knowledge** (spec/sync-opens.md §2-§3): "proofs only to a side that already knows them" is read so that a record found when only one side knows the other still counts.
- **A node keeping S unread shows its filter to every connection** (spec/sync-opens.md §4 Audiences; stated limit spec/sync-hostile.md §2): anyone holding S's public values learns it keeps S. Hiding it from unknown actors would hide it from the other holders too.

## Requirements conflicts (reversible as built; spec/requirements.md not edited)
- **Identity to a dialed key** (Offline and network): a dialer proves its identity to any key it chose to dial (a LAN announcer, a configured address); requirements say identity only to known actors. The private mutual recognition is not designed (sketch: pairwise DH beacons per known actor; cost at 10^5 known actors; rotating KEM keys).
- **What a sync holder learns** (Data a node cannot read; spec/sync-ids.md §2): a node granted sync learns the thing's tid, its granting account and which accounts' nodes open S with it. Proposed wording: "It must not learn identifiers, keys, values, authors, role grants, node identities, or structure beyond that, except that a node granted sync on a thing learns the thing's identifier, the account that granted it and the accounts whose nodes sync that thing with it."
- **A granter proves its account to the grantee's node** (Offline and network; spec/sync-opens.md §2, spec/sync-inbox.md §2): for the inbox re-send. Proposed wording: "A node shows which node, actor or account it is only to nodes of actors it already knows (it holds their keys), a node it granted access included. To any other node or a relay it shows only its address, whoever dialed."
- **Re-upload wording** (Data a node cannot read, Deletion): proposed "Reading never allows deleting data or forcing a writer to log it again." and Deletion's limit "a demoted holder can still delete what its old role allowed, until a writer holding the data logs it again."
- Flag only: "a node can limit abuse of data it cannot read without learning identities" may deserve softening, since a node keeping S unread learns which accounts' nodes open S with it.
