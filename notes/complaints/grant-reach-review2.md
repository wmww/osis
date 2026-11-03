# grant-reach-review2
> Summary: mishaps while re-reviewing grant-reach.
- `db.get(t, KEYS)` on a removed holder returns `None` once it dropped the thing, so "the seed did not change" and "it was dropped" look different only if you print both; my first probe of a removed person proved nothing.
- A leak probe by `seed(reader)` mixes paths: `t`'s own label leaked it too, so a fixed path still failed. Reading the entries under the one label told them apart.
- `git rebase ... | tail -1` in a one-shot script hid a conflict, and `tools/gate.sh` then passed on the half-rebased tree (HEAD at main, the branch's first commit staged). The gate could refuse to run with a rebase in progress.
