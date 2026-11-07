# Judgment vectors: what is still missing
> Summary: `core/test/vectors/judgment/` (format: core/test/vectors/README.md; generated and replayed by osis-node `tests/it/judgment.rs`) covers rule families, over-invite grants, a re-merge, two labels and referenced blobs; still missing: linked header lists, the secrets-side rotation scenarios, more re-merge shapes.
> Priority: low
> Tags: tests, permissions, retention, spec

## Left
- Linked header lists: a commit whose aspect list passes `CHUNK_THRESHOLD` (hundreds of aspects, about 300 KB of hex per file); pinned only by `hostile_host::linked_header_prefix_checked_spec_commits_4`, the waiting itself by the same path as a linked frontier. A demotion's linked frontier is pinned waiting only, its blobs left out of the bundle for size.
- crdt-model's pinned cases (`tests/props.proptest-regressions`) are join properties, not judgments: no vector.
- Re-merges of a nested write through a snapshot turning valid again (order seeds 1006, 12161 as found, 11-16 KB of bundle each): `rules.vec` has one simplified shape, whose read shows the creation coming back.
- Size: models.vec 83 KB, rules.vec about 400 KB, labels.vec 57 KB, blobs.vec 460 KB. Per file 26 KB of `setup` hex; a bundle is about 1 KB per commit, and a grant through `Engine::grant` on G adds about 20 KB (G gets secrets of its own: the setup's grants are bare writes). Pinned seeds left out (list in `judgment.rs` `found()`) could go in another file, at 26 KB of setup plus 5-25 KB each.
