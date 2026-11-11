# perm-append complaints
- A helper named `moved` collided with `place_shadowed`'s `moved` parameter (E0618, "call expression requires function"): the counter is `count_moved`.
- Editing sources while a `tools/heavy` run of the same worktree was still building made it unclear which code the first property run tested; reran after the last edit.
- Review: the new scale test cited no spec section, which only the gate (`tools/spec_map.py --uncited`) caught after a 2-minute build; workers could run it with clippy.
