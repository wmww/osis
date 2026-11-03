# grant-reach
> Summary: mishaps while tracing grants that reached nobody.

- `place_certificate_in` and `state.certs` key on (label, commit), not parts: placing a chain's `roles.0` of a commit first silently skipped a later copy of its `secrets.0`. Worked around by going through `certificates` (per part); the coarse key is still a footgun for the other callers.
- A pass runs only when a label is dirty, and nothing says so: a pass-dependent placement looks like "never" in tests and "in a few minutes" live. A test nudge (any write) showed it in one try.
