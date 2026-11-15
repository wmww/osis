# share-syncs
> Summary: workflow notes from the shared-here branch.

- Eleven sync tests (osis-sync flows/siblings, osis sync, engine certified) set up "S not yet in node N's sync set" by granting and not filing; sharing now syncs at the granter, so each needed an explicit `unshare`. Tests that state their premise through an incidental rule break when the rule changes: assert the premise (most did, which made the fixes quick).
