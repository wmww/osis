# A group.0 change reads the whole group
> Summary: Every applied change of a `group.0` (an add, a removal, a delete's removal) reads the group's whole state to refresh the group index (`apply::atomic::observe_state` → `Tx::state` → `pages::load_all`), so a membership change in a paged group costs O(group size) page loads, not O(change).
> Priority: normal
> Tags: engine

Measured while writing `scale::tid_removal_is_flat`: removing one member of a 10 000-item group loaded all 39 pages of its `group.0` (the same op on a plain `set<tid>` aspect loads 2-3). The set ops themselves page (the value index); the group index (`groups::def_of`) wants the whole definition. spec/requirements.md Scale: deleting costs what changed.

Fix direction: refresh the index from the delta (`groups::gains` is a start: what a delta newly lists, and what its value removals and element resets hide or drop), reading only the touched records, as refs do (`refs::Delta::reach`).
