# kit-cleanup
> Summary: Footguns met while trimming osis-kit.

- A rough duplicate-window scan (4 stripped lines repeated across files) found most of the merges here faster than reading; worth a tiny script in tools/ if cleanups recur.
- Six kit test modules each built `RenderRootOptions` by hand; a shared `render_root` in tests/it/main.rs now covers them. New GUI tests should use it.
