# partial-fetch-review
> Summary: Mishaps on the partial-fetch review.
- A 1 h `tick` in a test closes the connection (ping timeout), so "two passes later" ran no pass: `a_covered_body_stays_gone` passed with its check disabled for that reason, and because a co-writer deletes a re-upload within hops an end-of-test look at the host missed it. Look per round, and count passes.
- `Net.hold_blobs` holds a listing page that names the blob too, not only the fetch reply: set it after the listing.
- A sim-sweep piped through a `grep` for `test result|FAILED` hides its failure lines (it prints `FAIL` and `failing:`); rc=1 was the only sign.
