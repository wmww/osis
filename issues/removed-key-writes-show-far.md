# A removed key's writes show where no node holding the removal syncs
> Summary: Removals travel lazily (notes/write-path-design.md §2, D1 to D3): a thing no remaining member writes, whose readers are served only by stores no node holding the removal syncs, shows the removed key's later writes as valid until such a node syncs it. Open bug (decided: not something to build around); held-model counts it as the gap.
> Priority: normal
> Tags: security, sync

**What happens.** X removes stolen key K from A. K wrote D through [A] before, and writes D again after. D's readers drop the later write only once the removal reaches D, and it reaches D only where a node holds both: as evidence of a write it judges there (D1), in D's keyset at D's next rotation (D2), under the holder's sync ID and those whose keys open it (D3). Where no honest node syncs A (or another sync ID holding the removal) together with D, D's readers show K's later writes valid. spec/requirements.md allows it (a removal binds the nodes that receive it), but a thief can use it.

**The model.** held-model `evidence` judges each sync ID's reader against `World::reference` and counts where it differs from the node holding everything (`World::gap`); hand worlds `spec_evidence::gap_a_removal_no_node_holding_it_brings_leaves_the_write_showing`, `spec_reach::reach_*`, `spec_gaps::gaps_a_removal_on_a_path_through_a_read_hop_is_the_gap_once_it_decides`; notes/evidence-model-findings.md 38, 41.

**Candidates.** The reader's deposit on sight (write-path D4: a node holding the removal and a write it cuts, that cannot stamp the unit, deposits the removal's copy there) closes the part where some node reading the unit holds the removal (modelled as `Rule::deposit`, finding 41). Nothing closes the rest without a node holding both: delivery by the remover was dropped (Tess: no eager delivery).
