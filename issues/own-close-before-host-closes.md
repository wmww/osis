# `close` on `Runtime::Own` returns before the host store closes
> Summary: with `Runtime::Own`, `Osis::close` returns once the node store is closed but before the driver ends, so the host task may still hold `host.redb` (redb's file lock); reopening at once and hosting fails "host store: Database already open" (status `Failed`, no retry). `Runtime::Tokio` waits for the driver (`Net::ended`). Fix: wait for the driver on `Own` too, or retry the host store open. Low.
> Tags: api, host

- Seen while writing `hosting::stop_hosting_erases_host_store_spec_data_model_9` (it uses `Runtime::Tokio` for that reason).
