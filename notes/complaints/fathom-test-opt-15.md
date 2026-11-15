# fathom-test-opt-15
- `tools/cpuprof --report FILTER` matches a substring of any frame: `Engine>::follow` also takes `follow_rows`, `follow_certificates` called from queries, so "follow N%" there is not `follow`'s inclusive share.
- A planted fault must restore the old read order, not only the old read: a whole read placed after a short-circuiting `||` is never reached, and the mutation passes.
- A whole-binary cpuprof attributes a cached world's build to whichever test asks first: `introduce`'s share moves between identical runs (16% and 18%); compare by `tools/icount`.
