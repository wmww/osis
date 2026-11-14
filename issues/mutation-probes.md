# No shared tool for mutation probes
> Summary: the module briefs ask for a mutation table (break each rule, see a test fail); agents each write a throwaway script (`mut.py`, `mut.sh`, shell functions) and six lost uncommitted work undoing a probe with `git checkout <file>`, or let a reviewer's edit be overwritten by a running script restoring its copy.
> Priority: low
> Tags: tests, tools

A `tools/mutate.py FILE OLD NEW -- <cargo test args>` that refuses unless OLD occurs once, copies FILE aside, applies, runs the tests from a copied binary, restores from its copy (never git), and prints one table row (mutation, failing tests or "none") would make the table a loop and remove the footgun. A non-empty NEW only (a mutation script that "reverted" with an empty string inserted the original at the file's start).
