# prose-api-notes
- tools/policy.py (doc_refs) checks that a cited section name exists, not that the cited fact still lives there: moving a rule out of a section (e.g. api.md Rules -> Watching) passes silently; ~40 code comments cite api.md sections, checked by hand.
- api.md is dense rule text, nearly a fact per clause, and its Sync configuration and status section (7 KB) was off limits for net-6b: a 20-25% cut without losing facts was not reachable; ~11% on api.md came from duplicates with listener-design.md, signal-edits-design.md, client-port.md and lifetimes.md.
