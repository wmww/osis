# first-superseding-review
> Summary: mishaps met reviewing the hiders dating fix.

- A mutation dropping the state-before hiders in `Killed::note` passed all engine lib tests: a kill row dated late is allowed (never early), so only a test timing when leaving is told catches it. Row dating needs a told-at test per superseder source, not only never-early checks.
- Chaining `claudewait A || claudewait A` in one call overran the tool's timeout; one wait per call.
