# review-wedge
> Summary: footguns met reviewing wedge-fix.

- A full branch diff (42 KB) spills to a tool-results file and needs a second read: `git show --stat` first, then the diff per directory.
- An engine `DiagnosticKind` with an `Option` commit translated to an osis variant with a required one silently falls to `Handled` when the engine sends `None` (Fault from a Prove trial): nothing flags the dropped case; check every `tell_*` caller's commit against the osis variant's field type.
