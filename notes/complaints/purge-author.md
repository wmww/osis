# purge-author
> Summary: footguns met while renaming the purge author and building the delete-key tests.

- `tools/mutate.py` refuses two rows planting one site (a control row `A` beside `A + B`): "two mutations overlap", after nothing ran. Two invocations, two builds.
- spec_map anchors: a section heading is no "text of §N" (`§4 (Logged again once)` refused), and an anchor wrapped over two comment lines gets two spaces and fails; the `spec/x.md` and its `§N` must also share a line.
- A Delete handed to `Store::take_delete` in a sync harness test changes the store but tells no peer until node 1 restarts (`power_off`/`power_on`): a test of what peers do after a delete needs that restart.
- Grep for `actor` over the tree gives about 3,500 hits, mostly the requirements' actor (holders, client actors, key actors): a rename of one meaning has to go by the fields and functions that carry it (`view.acting`, `Fact.actor`, `Stamp.actor`), then the compiler, then a phrase grep of comments.
