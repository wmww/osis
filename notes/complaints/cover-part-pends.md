# cover-part-pends
> Summary: Workflow notes from the atomic-wait-by-listing change.

- `tools/spec_map.py --check` prints "wrote notes/testing-map.md" though it changed nothing; unclear whether `--check` writes.
- The node test constants `REG`/`TAGS` are typed `Aspect<Value>`, while engine calls take `Ak`: tests mix `ak("/t/tags")` and `&TAGS`; a compile round each time.
