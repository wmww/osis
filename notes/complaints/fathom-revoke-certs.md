# fathom-revoke-certs
- `Engine::holds_commit` and `body_valid` mislead as observers in World tests: a hand-opened deposit read `holds_commit` false and `body_valid` None while `get` returned its value. Assert on reads.
- A demotion reaches a node by two independent paths (chain certificates' edge writes, and the demoted actor's keysets carrying it); a mutation check must cut both, or a test looks load-bearing when it is not.
- A reader of t also syncs t's reader actor's home, which carries every edge write into t: a test that the demotion travels under another S must cut the reader off from every node but a store of S.
- An honest demoted writer that reaches S learns the demotion and logs its later write nowhere, so "the write arrives after the certificate" needs the deposit handed in (`streams::opening`).
