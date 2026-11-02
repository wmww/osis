# An absolute keep at most alone never drops a body
> Summary: spec/commits.md §5 says every node drops a body by its absolute keep-at-most bound; a body with no relative bound never is (`check_at_most` runs only from deaths, and only bodies with a relative bound get those). Building it needs a carrier first: a drop on the `retention::on_parts` path lost live writes never uploaded.
> Tags: engine, sync, retention, security

Today the erased data stays past T, in the body at every node and at hosts. A body with a relative bound too acts on T only once it has a death.

Tried and removed (branch atomic-carrierless): `check_at_most` from `retention::on_parts` for a held part with an absolute bound. A body drops before it was ever uploaded, and with no carrier (`snapshot_first` runs only for an entry at a host), so the writer reads v1 and a reader reads nothing: T already past at the write, or passing while the writer is offline. Regressions to keep: `timed_dead::absolute_bound_past_at_write_reaches_reader_spec_commits_5`, `absolute_bound_passing_offline_reaches_reader_spec_commits_5`.

A build needs: a live body's carrier written and placed, or the body uploaded, before the drop, at T and on a commit arriving or made past T; a part still missing not dropped, so its late copy still joins (it was dropped once: the late live write was refused); hosts' copy deleted through the carrier rule (`deletable` already does).

Oracles do not catch this class: `order::keep_of` and `random_step` never draw an absolute bound, and `order::carrierless_history` only relative ones. Add absolute bounds there with the build.

Atomic apply needs no change for it: a passed T counts only with a later commit on the aspect, since a live body leaves only with a carrier (spec/commits.md §4).
