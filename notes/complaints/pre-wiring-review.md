# pre-wiring-review
> Summary: workflow notes from reviewing the Opens 21-23 branch.

- A raw role write through `Engine::commit` is refused by the role check even with `skip_writer_rules` set; `commit_hostile` (which also marks the mutation unchecked) is the way to build another implementation's commit in a test.
- No generator makes a commit whose parts on a thing differ in need, so a drop rule's control reads every generated world alike; a quick count of differing readings over `tiny_world` (judge under both rule sets, compare `observed` and `applied`) answers that in seconds, before any gate-size run.
