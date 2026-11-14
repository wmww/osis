# forgotten-offline
- The issue blamed node sync, but the cause was the tests: `let _ = net.sync(b).handle(Tick)` on an offline node drops its `Action::Dial`, which then never gets `Up` or `Down`, so b had no connection once back online until a restart reset `conns`. Printing in `run_dirty` (passes due, connection states) found it in a few runs; reading the delete and memory code first did not.
