# api-design
> Summary: Mishaps while writing the API review.

- A `grep -r` over `app kit` took over 2 minutes because it walked their `target/` dirs: search `git ls-files` instead.
- Main moved twice during the gates; a docs-only rebase re-gates each time.
