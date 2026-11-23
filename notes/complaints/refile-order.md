# refile-order
> Summary: workflow snags met fixing the refile-order dependence.

- `why_role`/`why_kept` show the walk's context (`Read(T)`) but not why `Core::enter` took it (which epochs counted, own or read through the mint admin): finding that took a temporary engine hook printing `is_independent`, `enter` and `ix.secrets`. A why-entered line in `why_role` would have shown it at once.
