# api-flake
- Flake shape: a test writes twice, then expects one `on_change` call per write. Calls coalesce (a late call reads the latest state), so under load the first call already shows the second write. Take each value before the next write. Old test failed 8/40 beside 16 busy loops plus a full `it` run; alone it never failed.
- `tools/bin-at main OUT -p osis --test it` was the quick way to get the old binary for the old-vs-new load run.
