# sync-tests-cleanup
> Summary: Footguns met cutting osis-sync it's cost: policy.py reads untracked scratch tests, mutate.py OLD must be unique, the brief's footgun files no longer exist, per-test vs per-module cost.

- The brief pointed at notes/complaints/rotation-tests*.md and engine-it-tests*.md for footguns; neither exists any more (handled complaint files are removed), so the lessons live only in notes/test-harnesses.md.
- A scratch `#[ignore]` probe test in tests/it fails `tools/policy.py` (spec_map: uncited test) even uncommitted: keep probes as a patch in the scratch dir and apply them only to build.
- `tools/mutate.py` refuses an OLD occurring twice in the file, and a loop's iterator like `self.held.get(&s).cloned().unwrap_or_default()` often does: there is no way to name the second site.
- Fixture builds dominate the per-test profile (world_of(0, 4, 4) 27 G, (0, 3, 3) 11 G, siblings 6.5 G, contacts 3.2 G, two_nodes 0.65 G; measured by a scratch test building only each), but under the gate (one process per binary) each is paid once: a cache inside one module moves the module count, only fewer tests move the per-test sum. Say which metric a brief targets.
- The memo debug comparisons `history::world_of` turns on cost only 6-10% of a world-built module (growth:: 155 G -> 145 G off): not a lever.
