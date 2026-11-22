# A delta linking a page twice: what its blob wait lacks depends on order
> Summary: `apply/reach.rs` checks each page at the place a pass first reaches it and skips it after; a delta linking a page twice (decoders refuse it, "a page linked twice") is checked at whichever place comes first, so whether the walk refuses a tree, and what it lacks, can differ between arrival orders and a reload's fresh derivation.
> Priority: low
> Tags: engine, tests

- Who writes the input: any writer of a commit a node keeps pending. The part never applies either way; what differs is when it is refused and what is fetched meanwhile, and `Engine::check_walks(true)` at drop would fail on such a world.
- A pass does not know what earlier passes reached (walk memory is the frontier only), so a page reached again in a later pass is walked again at its second place; a pass costs at most the held blobs it reaches, once each.
- Shape of a fix: refuse every tree of a walk (it lacks nothing; the decoders then refuse the part) at a page linked twice, found the same in every order, without keeping per-walk state per held blob. No test builds this yet.
