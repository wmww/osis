# review-addenda complaints
> Summary: reviewer of addenda-trigger: a loop guard's bound computed eagerly costs release builds a whole read.

- `LoopGuard::round` takes its bound as a closure, but the size it reads was computed before the call (`closure.things().count()`, O(node closure) per round in release, where the guard counts nothing): compute the size inside the closure.
