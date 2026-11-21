# Sync decisions waiting on Tess
> Summary: The reversible sync choices built or specified while Tess decides, and proposed spec/requirements.md wordings (not applied) where the sync spec goes past what requirements allow; each with what is built now and the option.
> Priority: low
> Tags: sync, tess-call

Each is built or specified the reversible way; one decision each.

## Behaviour
- **Dial hints** (spec/sync-inbox.md §2, spec/wire.md §10): every node publishes `reach.0` and lists itself in its account profile's `dial^.0` (`osis_engine` `dial::lists_on_profile`); links and contact cards carry the sharer node's dial hint by default. Options: which nodes a profile lists; hints off by default (issues/privacy.md).
- **A node keeping S unread shows its filter to every connection** (spec/sync-opens.md §5 Filter; stated limit spec/sync-hostile.md §2): anyone holding S's public values learns it keeps S. A policy limiting whom it syncs with (spec/sync-opens.md §1 Policy) hides it from the rest.

## Requirements
The re-upload wording below goes with issues/demoted-writer-deletes-at-stores.md.

## Proposed, not applied
- **Re-upload wording** (Data a node cannot read, Deletion): proposed "Reading never allows deleting data or forcing a writer to log it again." and Deletion's limit "a demoted holder can still delete what its old role allowed, until a writer holding the data logs it again."
