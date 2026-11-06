# Spec questions left by the spec refactor
> Summary: Two spec rules the code may not meet (a commit of an unknown format version, ephemeral writes by a shared key actor); found in the no-meaning-change refactor and not settled there.
> Tags: spec, commit

- **Unknown format version**: spec/versioning.md §2 parks it and spec/commits.md §4 lists a parked commit as pending, but `Header::decode` answers `Error::UnknownVersion` and neither core/engine nor core/node names that error or `UnknownFormat`. Check whether such a blob is kept, relayed and re-examined.
- **Shared key actor, ephemeral content**: spec/commits.md §3 has a key actor used from several nodes (link key, recovery key) use commit form, and an ephemeral content commit use session form. `validate.rs` refuses the first shape. Decide whether such an actor may write ephemeral data, and say so.
