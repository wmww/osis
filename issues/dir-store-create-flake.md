# Real directory stores failed create once, untraced
> Summary: One tier-1 run failed 5 tests at `create().unwrap()` on real directory stores with no error text kept; `/tmp` (tmpfs) was 25 of 31 GB full then. Three clean tier-1 runs after, at 12 GB. Unexplained; a full `/tmp` is the likely cause, not proven.
> Priority: low
> Tags: tests, store

Seen on branch net-connect-lan-base, by the worker: `ephemeral::restart_forgets_ephemeral`, `port::listen_socket_names_the_store`, `serving::own_runtime_close_frees_serving_store`, `serving::stop_serving_erases_its_store`, `runtime::own_runtime_reopen_right_after_close`, in one run of osis `it`; the same tree passed right after. The log was filtered, so the `Error::Storage` text is lost.

Known:
- All five open real directories under `temp_dir()`. Create fails only through `std::fs` / redb calls in `parts()` and `open_salt` (`Error::Storage`). One of the five has no runtime and none binds a real LAN socket (`Opening` defaults `Lan::Off`, and they use in-process transports or none), so no per-store socket, fd or LAN port is involved.
- `ulimit -n` here is 524288, so fd exhaustion is unlikely.
- Next time: keep the unfiltered log; check `df -h /tmp` and the error text before calling it a flake.
