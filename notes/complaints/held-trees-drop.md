# held-trees-drop
> Summary: workflow notes from the held-trees-drop task.

- `Engine::held_links` already names another thing (link seeds): the first name picked for the chunk-reference cache clashed; grep a method name across the engine before choosing it.
- A filtered `cargo test` piped through grep hides the scale tests' printed counts; rerun the one test with `--nocapture` to read them.
