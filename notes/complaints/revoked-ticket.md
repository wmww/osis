# revoked-ticket
> Summary: Complaints from the revoked-ticket job (sibling-step store stuck).
- The issue's diagnosis (a ticket word outliving the removal) came from `why_role` on the unshrunk history; shrinking first showed no write grant at all and the cause in step registration. Shrink before diagnosing from a role dump.
- `inbox::register::plan` returns `Nothing` silently when the source's head is off the recorded path; no trace line says so. A `trace::note` there (source head off the recorded path) would have saved two traced replays.
