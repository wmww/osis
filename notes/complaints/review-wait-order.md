# Complaints: review-wait-order
> Summary: footguns met reviewing the ordered path wait: a scale test was missing for a recursive judgment, and the order DSL hides which pack is which.

- The path wait's recursion was memoized per write, not per edge: each write reading an edge rescanned that edge's unjudgeable prefix, quadratic in forged held writes (72 -> 3600 reads, n 4 -> 40). No scale test covered it; a recursive judgment wants one at birth.
- Finding a Step's pack in order.rs means decoding headers (`aspects(i)`, `authors`): no step -> pack map.
- The gate's NEW-SLOW fired on 8 sync/cli tests at load 46; icount of main's vs the branch's binary matched within 0.01%: wall-time flags under load cost a bin-at build and two icount runs to clear.
