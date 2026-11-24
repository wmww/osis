# review-refs-date
> Summary: Footguns met reviewing the one-presence-write-per-position branch.

- The branch's own proptests passed with the fix and with it reverted until the generator wrote two composite encodings created empty at one position; only `crdt_equals_model`'s reach check (gate size) found the second site the rule moved (`Fragment::reach` treated a `W`-writing delta as a footprint while the join drops a slot whole). A rule change in prune wants a grep for every place that mirrors prune's reach (`kept_reset`, `reach_with`).
