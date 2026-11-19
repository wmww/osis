# Content dropped outside the node closure is lost when the thing returns with its record
> Summary: A thing whose content was dropped as not carried (spec/commits.md §4 Outside the node closure) and that then went whole is unknown again; when its minting commit comes back with a now-valid strong to it, record and strong arrive in one transaction, so nothing is pulled anew (spec/sync-judgement.md §3 Dropped bodies) and the thing's other content commits, whose entries the node already knows, are never fetched again. main loses the same content the same way (there it applied and was stripped).
> Priority: normal
> Tags: engine, sync, spec

## How it shows
No repro built. The path needs, at node N reading X:
1. M (author A) mints dependent W with X's strong to it; N judges M's strong part invalid (dropped as invalid) while W's record part stays valid (W's mint admin a thing A still writes, not X), so M is held, W outside the node closure.
2. D (content on W) reaches N under X's sync ID from a source that judges the strong valid. N holds W's minting commit, so D counts as never received at the pass end; W, needed by nothing, goes whole with M.
3. The strong turns valid (a re-grant of A on X, spec/permissions.md §5.2), and M is fetched again as a part dropped invalid that turned valid (spec/permissions.md §6): its record and strong arrive in one transaction, so `units::refetch` pulls nothing (`Core::learned`); N's store knows D's entry, so D is not fetched.

When the record outlives the content (M missing a part on a thing of the closure keeps its header), the strong finds the record held and pulls anew: `outside::content_dropped_as_not_carried_comes_back_when_the_minting_strong_does_spec_sync_judgement_3`.

## Reach
Honest nodes: a strong judged invalid at one node and valid at a source (concurrent admin edits), then made valid by a re-grant, with content on the thing written meanwhile. Rare; content is lost at that node only, other holders keep it.

## Options
- The same-transaction exception only for the minting commit arriving for the first time: "first time" is not knowable once the thing went whole without a durable mark.
- A durable mark per thing whose content was dropped as not carried, kept while its record is not held; a strong reaching a marked thing pulls anew even with its record arriving in that transaction. New state with its own flood bound (a hostile writer can make content on many things whose minting commits a node holds).
- On a strong newly valid in a part judged invalid before (the re-grant path alone), pull anew regardless: narrow, as rare as the path; check it covers every way a thing goes whole with its record.
