# members-cost-review
- A flow test's `w.run()` looks like "no clock passes", but `w.create` plus `w.place` is a group write: every label passes anyway, so it says nothing about a narrow mark. Only a bare edit of a placed thing tests `mark_dirty_of`.
- libtest captures `eprintln` of passing tests: a probe's lines vanish without `--nocapture`.
