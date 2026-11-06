# CLI reference lives in the code
> Summary: The CLI's commands are documented once, in `cli/src/args.rs` doc comments (`osis --help`). The rest of the precise reference (value syntax, JSON mapping, exit codes) still lives in notes/cli.md; move it into the CLI's own help (help topics or `long_about`), so one place states it and notes keep only design and reasons. Autonomous work.
> Tags: cli

Tess: no second copy kept in step by a test. The command table and its check are gone. For the rest: `osis help values`, `osis help json`, `osis help exit-codes` (or the clap equivalent), written from notes/cli.md's sections, then those sections leave the note. Tests in cli/tests/it/syntax.rs cite the note's sections; point them at the help topics.
