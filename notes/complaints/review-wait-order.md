# Complaints: review-wait-order
> Summary: footguns met reviewing the ordered path wait: a scale test was missing for a recursive judgment, and the order DSL hides which pack is which.

- The path wait's recursion was memoized per write, not per edge: each write reading an edge rescanned that edge's unjudgeable prefix, quadratic in forged held writes (72 -> 3600 reads, n 4 -> 40). No scale test covered it; a recursive judgment wants one at birth.
- Finding a Step's pack in order.rs means decoding headers (`aspects(i)`, `authors`): no step -> pack map.
