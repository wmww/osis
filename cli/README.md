# osis-cli

`osis`: the osis API from the command line, for scripts, debugging and agents. Each run opens
the store, acts, and closes it. Values print in a text form that reads back as input; `--json`
gives machine output. Full reference: `osis --help` and notes/cli.md.

```sh
export OSIS_STORE=/tmp/demo
osis init                                        # prints me, node, home
t=$(osis create --owner me --in home /note/title '"groceries"')
osis set $t /note/tags '#{"food"}'
osis op $t /note/tags '' add '"weekly"'
osis show $t                                     # every aspect, groups, role
osis get $t /note/tags                           # #{"food", "weekly"}
osis --json get $t /note/title                   # "groceries"
printf 'create --owner me --in home --as a /x/n 1\nset $a /x/m {1: [true]}\n' | osis write
osis commits --thing $t; osis undo --thing $t
osis --schema todo.osis get $t /todo/task        # named fields with a schema
```

Exit codes: 0 ok, 1 other, 2 usage, 3 absent or unknown, 4 not allowed, 5 type or too large,
6 network or timeout, 7 invalid, 8 store missing or locked.
