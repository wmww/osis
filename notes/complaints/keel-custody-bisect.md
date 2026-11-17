# keel-custody-bisect
- `git bisect run` over the custody replay worked well: one seed per step, ~1.5 min a step (most of it the rebuild), 4 steps.
- The `claudewait` skill name in the skill list is not a callable tool; `claudewait ID` in Bash is.
- The brief's "harness or engine" framing hid that the failures had nothing to do with t epochs: the cue was an `u` listing waiting forever (a `writable_now` probe found it in one run).
