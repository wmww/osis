# dogfood-rehearse complaints
> Summary: workflow notes from rehearsing the dogfood flow over real sockets.

- Real-socket behaviour (dead connections left by an exiting process, restarts) shows only on real sockets: the scripted and mem harnesses close both ends at once, so the 60 s idle-timeout stalls never appear in tests. The quic tests are `#[ignore]` (by hand), so the stateless-reset test runs only when asked.
- A rehearsal without `--no-lan` heard other nodes on the box over LAN discovery (and could reach the real dogfood's): any by-hand multi-store run on this box wants `--no-lan`.
- In a tokio test, `shutdown_background` frees an endpoint's socket asynchronously: rebinding its port right after races (`Address already in use`); `shutdown_timeout` waits for the workers.
