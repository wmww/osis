# kit-cleanup
> Summary: Footguns met while trimming osis-kit.

- Six kit test modules each built `RenderRootOptions` by hand; a shared `render_root` in tests/it/main.rs now covers them. New GUI tests should use it.
