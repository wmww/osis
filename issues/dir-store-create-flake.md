# Real directory stores failed create once, unexplained
> Summary: One default-test run failed 5 tests at `create().unwrap()` on real directory stores; the text was lost to a filtered log. `/tmp` (tmpfs) was 25 of 31 GB full then. Not reproduced under repeats at 1 and 2 cores; a full `/tmp` is the likely cause, not proven.
> Priority: low
> Tags: tests, store

Tests seen: `ephemeral::restart_forgets_ephemeral`, `port::listen_socket_names_the_store`, `serving::own_runtime_close_frees_serving_store`, `serving::stop_serving_erases_its_store`, `runtime::own_runtime_reopen_right_after_close`.

- All five open real directories under `temp_dir()`. Create fails only through `std::fs` and redb in `parts()` (`Error::Storage`). One of the five has no runtime and none binds a real LAN socket, so no per-store socket or LAN port is involved. `ulimit -n` is 524288.
- A store open failure names the directory (`handle.rs` `parts`, test `runtime::a_store_it_cannot_write_names_the_file`), so the next failure's panic says which store and why.
- A passing default-test run leaves nothing under `$TMPDIR`; a test that panics leaves its small directory. A real-directory store under test is at most a few MB.
- Next time: keep the unfiltered log; check `df -h /tmp` and the error text.
