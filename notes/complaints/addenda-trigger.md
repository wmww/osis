# addenda-trigger complaints
> Summary: worker addenda-trigger's footguns: the issue file was never committed, an order failure inside `play` prints no dump, a fixpoint loop's peek at a feed must skip rolled-back entries.

- The issue file existed only untracked in the main checkout (the known-failure commit named it but did not add it): a worktree claimed from main had no copy to read or delete.
- A shrunk order history that fails while being played (the missed-trigger check in a peer's own commit) prints nothing under `OSIS_ORDER_DUMP`: the dump runs per delivery order. A backtrace (`RUST_BACKTRACE=1` on the copied binary) showed it was `play_with`.
- `Feed::added` lists keys a failed step's rollback took out again: a loop deciding "something entered" from a cloned feed spun until its guard (`an_answer_undone_owes_no_holding_of_what_it_wrote`) until it checked the key is still present.
