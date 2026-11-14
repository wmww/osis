# sync-models complaints
> Summary: Footguns met while writing NetHold/NetDestroy/NetKeep.

- TLC weak fairness on a disjunction of honest actions let one reader's Sync starve and reported false liveness loops; fairness must be per action and per entry (and strong for stream reads).
- A hostile writer with unbounded deletes made a 3-body model explode (millions of states in a minute); bound its deletes (`MaxH`).
- The spec changed under the model mid-task (full peer, ephemeral presence); a model brief should name the spec commit it models.
