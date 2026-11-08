# A body killed judges every entry of its label
> Summary: Under purge on replace, a write that kills one body of a big aspect makes the writer's next pass judge every entry of the label for deletion (23 at 20 keys: the bodies of two aspects), where one more key judges 1. Bodies judged stay flat. Repro: osis-node `scale::repro_kill_judges_label_entries`.
> Priority: low
> Tags: node-sync, performance

spec/requirements.md Scale wants a change to one body to cost O(change). The entries come from the deletion step's scope (`pass/delete.rs` `deletions`, `scope_entries`): the kill's scope reaches the whole label, not the killed body's entries. The other steps of `scale::aspect_pass_is_flat` (a new key, an expiry, a write under a big closure) stay flat.
