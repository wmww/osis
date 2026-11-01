# durable-apply
> Summary: footguns met while streaming the engine's apply (issue durable-decode-bound step 3).

- `wt` was not on PATH in the agent shell although the plugin is installed: ran it as `~/.claude/plugins/cache/wmww-agent-skills/reasonable-rust-builds/0.5.1/bin/wt` (`claudewait` was on PATH).
- `scale::big_map_apply_memory` reports later steps as "+0 MiB": glibc keeps the earlier steps' freed memory, so a step that got cheaper reads as nothing. Run it with `GLIBC_TUNABLES=glibc.malloc.trim_threshold=0:glibc.malloc.mmap_threshold=65536` to see each step's own peak; one run at 10^6 is about 8 minutes per binary.
- `gen` is a reserved keyword in edition 2024 (a loop variable named so fails to parse).
- A differential with "break the piece order" as its mutation check cannot fail: pieces of one delta join commutatively. What it does catch is a piece's page write skipped before eviction. A skipped page write in the reset path is masked too: loading a page joins it under the skeleton's reset, which prunes it again (only the stored bytes differ).
