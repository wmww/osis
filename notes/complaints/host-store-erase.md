# host-store-erase
> Summary: mishaps met while erasing the host store on stop.

- `close` with `Runtime::Own` returns before the driver ends, so the host store (`host.redb`, redb's lock) may still be open right after it: a test reopening `host.redb` failed "Database already open". Tests that inspect the host store after `close` need `Runtime::Tokio` (close waits for the driver there).
