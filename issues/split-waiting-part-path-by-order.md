# A split commit's waiting part has its path decided or not by arrival order
> Summary: where a split commit's part on thing D waits (pages, parked, unjudgeable), `View::paths` holds D's opened path if the part came with the commit's first copy (`atomic::apply` decides by every key the blob carried, and the applied record keeps the key) and not if it came later (`apply::late_parts` keeps the key with the waiting copy alone): one held set, two index states. No test shows a read differing; the parts row and what `Engine::package` sends differ.
> Priority: low
> Tags: engine, tests

Seen in `validity::an_entry_opening_under_two_keys_judges_alike_in_any_order_spec_wire_4`, which states both orders as they are (D's path opened with the commit where `one` came first; else D's part waiting with its key).

Either direction makes it one state: a waiting part's thing key kept with the waiting copy only (the applied record carries keys of joined parts alone, `Meta` decided from those), or a late waiting copy's keys learned into the applied record. Learning into `View::paths` alone is not enough: the index must stay a function of the stored commit records (`check_index`'s rebuild).

Reach: parts of split commits wait more often since the wait reads the stated path (a path through things nobody granted is unjudgeable, notes/engine-apply.md). `order::held_set_decides` plays split commits with late parts; a failure there naming a split commit's validity flags or digest by order is this.
