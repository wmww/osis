# split-form
> Summary: mishaps met building the split path form.

- A full `cargo build --all-targets` after touching osis-commit takes 4 to 5 minutes; every round of compiler errors in a downstream crate costs that again. Building `-p osis-engine` alone first, then the rest, halved the waits.
- The engine's rebuild check (index from commit records against the live index) caught a view that differed only in which split paths the load could decide: a decision taken from secrets must be redone at load (`paths::refresh` at the end of `apply::load`), or the check fails far from the cause.
- Regex-replacing a method call (`acting_on(x)`) whose argument held parentheses left unbalanced code in two places; hand edits per site were faster.
