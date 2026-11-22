# review-refs
> Summary: Footguns met reviewing refs-overcount.

- The crdt model generator puts references only in set elements (`gen::elem_value`): a reach check narrowed to references checks nothing about map, sequence or enum reach. A mutation dropping the map's same-key fixpoint passed the narrowed check.
- The engine's raw `Mutation::op` writes unvalidated values: the refs reproducer adds `List[Strong]` to `t:refs.0` (`set<ref>`), which the writer's view cannot type, so a later `Op::Remove` of it through `REFS` is a no-op (spec/crdt.md §9 opaque). Looked like a remove bug until the view was checked.
