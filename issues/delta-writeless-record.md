# A delta may carry a set or bag element record holding no write
> Summary: both decoders accept a delta whose set element is `[Dot, [], []]` (no reset, no value), a record prune drops (§4.2: a record with no surviving write goes), so a fragment that is not prune-stable as a fragment (only as its writes) decodes. Rule 7 rejects the sequence analogue (a run carrying no write) but states nothing for set, bag or map records.
> Priority: low
> Tags: crdt

Seen as the one difference between `prune_stable` by fragment equality and by carried writes (`Fragment::carried`) in `tests_decoder`'s differentials. Harmless to state (it joins to nothing) but non-canonical: a state never holds one. Fix: one §3.3 rule 7 line (a record carrying no write, in any collection) and the check in both decoders, or `prune_stable` by equality once nothing else prune drops can be carried.
