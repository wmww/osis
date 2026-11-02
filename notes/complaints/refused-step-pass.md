# refused-step-pass
- `Net::restart_host_with` then `advance` alone leaves nodes disconnected: `advance` ticks before the queued Close runs, so the redial waits for the next tick. Call `net.run()` first (as the existing tests do); cost a few debug runs.
- `assert_eq!(read(removed, t), Some(old))` fails with `None`: a removed reader drops what only its lost secrets read. Assert `assert_ne!(.., Some(new))`.
