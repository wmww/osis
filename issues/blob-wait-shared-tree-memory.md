# Waiting commits sharing a page tree each keep a walk of it
> Summary: each pending commit's waiting slot keeps its walk (`reach::Walk`: `reached`, `missing`, a `LinkTree` per position) in memory; W small forged commits linking one large held page tree, each lacking one page never sent, keep W walks over the whole tree: RAM about W × the tree's links while the store holds the tree once plus W small commits.
> Priority: normal
> Tags: security, engine

- Who writes the input: any writer of commits a node waits for (a forger reusing another commit's links, as `tests_paged::commits_sharing_pages_are_each_woken_once_per_page_spec_commits_4` builds). W is bounded by what pending commits a node keeps (carriers, peer budgets); the tree by the held pages.
- Memory per walk is about 100 bytes and more per link reached (`reached` holds every blob reached, `missing` the frontier); main kept the same walks per waiting commit (its `Walks::walks` cache), so this is not new with keyed waits.
- Fix shape: share walk state per page tree (a tree's walk keyed by its root list, slots referring to it), or keep `reached` only per held page once, not per slot; the bound should be O(held bytes + pending commits).
