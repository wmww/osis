# cleanup-cli
> Summary: Complaints from the osis-cli cleanup.

- dead_pub, spec_map and policy found nothing in cli/; the volume was copies (two watch-page loops, text and JSON built in two passes, a private copy of `osis::Store`). A 3-line repeated-window scan over cli/src found the first targets in seconds; the brief could name that scan.
- The CLI is near its floor without changing what it does: most of its 3.9k lines are one-line-per-command parsing and printing, the value parser and the serving flags (the latter go with net-one-peer 6b). The next real cut is the serving/admission code once 6b lands.
- notes/cli.md said `card show` and `leave` wait on `All`; the code waits on the profile and the thing. Notes describing per-command details drift; the help text is the one reference.
- Review: `tools/bin-at` builds only test binaries; main's `osis` binary for the text differential came from the `target/debug/osis` that `bin-at main OUT -p osis-cli --test it` leaves behind (copy it before the next build). A `--bin NAME` option would make that deliberate.
