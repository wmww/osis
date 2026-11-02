# order-harness-teeth
- A failing large order run costs 3-5 minutes (each failing seed shrinks one at a time, about 10 s each), so triaging 30+ failures in a row is slow; a `--no-shrink` setting would help triage.
- The order harness's shrink is one pass and keeps long histories for partial-set failures: reading them by hand was the slow part.
- `ls -t` over the shared tasks dir picks another agent's task: use your own background ID with `claudewait`.
