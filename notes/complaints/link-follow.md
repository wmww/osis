# link-follow
> Summary: workflow snags met on the link follow-time branch.

- A stray `cat > file` with no stdin in a compound command hung the Bash call until stopped (it read the tool's stdin): my slip, but the hang shows only as a timeout.
- The sync World harness exposes no node wake, so a deadline's own wake cannot be checked there (the redial timer hides it); the engine-level test of `Engine::reached` covers it.
