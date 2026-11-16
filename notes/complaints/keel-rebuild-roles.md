# keel-rebuild-roles
> Summary: Mishaps met fixing the rebuild/live roles-secret disagreement.

- `check_index`'s secrets diff prints two whole `ActorEpochs` maps on one line each (650 KB log); finding the differing epoch took a sed/diff split by hand. A per-epoch diff in the message would save that.
- The differential's failure names no peer or thing; finding which engine mutation lost the epochs took a temporary dump at every `ix.secrets` write.
