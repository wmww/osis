# g-dropped-review
- The worker dropped "or the commit awaits its record" from spec/commits.md §5 needs as subsumed by `Root::Awaited`; the code's `pend_needs` still carries the awaited thing and removing it fails 9 osis-engine lib tests. A spec trim with no code trim beside it is worth a check in every review.
