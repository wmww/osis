# Sync decisions waiting on Tess
> Summary: The reversible sync choices built or specified while Tess decides, and two proposed spec/requirements.md wordings (not applied) where the sync spec goes past what requirements allow; each with what is built now and the option.
> Priority: low
> Tags: sync, tess-call

Each is built or specified the reversible way; one decision each.

## Behaviour
- **Sync-only holders keep no subgroups** (spec/sync-set.md §4): a grant is per sync ID, so a new subgroup is kept only once granted too; an app policy may grant new subgroups.
- **Dial hints** (spec/sync-inbox.md §2, spec/wire.md §10): every node publishes `reach.0` and lists itself in its account profile's `dial^.0` (`osis_engine` `dial::lists_on_profile`); a grant shows the grantee the granting node's dial hint; links and contact cards carry the sharer node's dial hint by default. Options: which nodes a profile lists; hints off by default (issues/privacy.md).
- **A node keeping S unread shows its filter to every connection** (spec/sync-opens.md §5 Filter; stated limit spec/sync-hostile.md §2): anyone holding S's public values learns it keeps S. A policy limiting whom it syncs with (spec/sync-opens.md §1 Policy) hides it from the rest.

## Requirements conflicts (reversible as built; spec/requirements.md not edited)
- **What a sync holder learns** (Data a node cannot read; spec/sync-ids.md §2): a node granted sync learns the thing's identifier (its opaque tid: never its creation record or the tids of what a group holds) and the granting account, nothing more. Why the tid: the grant reaches it as the granter's signed role commit, which names the thing, and its account files the thing by tid in its synced group so its nodes know what to keep. (Which accounts' nodes open S with it is theirs to show: spec/requirements.md, Offline and network.) Proposed wording: "It must not learn identifiers, keys, values, authors, role grants, node identities, or structure beyond that, except that a node granted sync on a thing learns the thing's identifier and the account that granted it."
- **Re-upload wording** (Data a node cannot read, Deletion): proposed "Reading never allows deleting data or forcing a writer to log it again." and Deletion's limit "a demoted holder can still delete what its old role allowed, until a writer holding the data logs it again."
