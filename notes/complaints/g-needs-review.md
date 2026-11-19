# g-needs-review
> Summary: Footguns met reviewing the certificates rule.

- A cost test that varies only what is held in the node closure cannot see a pass end judging every held thing: the filter to things outside the closure is uncounted. Count what is due before filtering (`needed: things due`).
