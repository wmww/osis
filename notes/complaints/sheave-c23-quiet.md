# sheave-c23-quiet
> Summary: finding what a missed skip changed took hand-patched backtraces twice (store transaction begins, stamp writes on this thread); a passing test hides its eprintln diff.

- Two worlds differing only in the pager's version took a backtrace patched into `Store::transaction` to trace, then another patched into `Table::log` to find which write broke `holds_here`. Frames of generic closures print kilobytes of type names. A by-hand probe var printing a short caller line (osis frames, generics stripped) for each store transaction begun and each counted stamp write would have found both in one run.
- A softened assertion (`eprintln` instead of `assert_eq`) reported nothing because libtest captures a passing test's output; an experiment printing a diff must panic or run with `--nocapture`.
