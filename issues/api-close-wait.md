# `Osis::close` returns Ok while the database is still held
> Summary: `close` waits `CLOSE_WAIT` (5 s) for the database to close and then returns Ok regardless; when the last holder is a dispatcher callback or a sync engine call that outlasts it (not another handle), the promised "can be opened again at once" fails.
> Tags: api

Found by the arbitrary-values audit. `handle.rs` `close`: `rx.recv_timeout(CLOSE_WAIT)` cannot tell "other handles keep it open" (documented, fine) from "the dispatcher or driver still holds it". Fix direction: count the other user handles before dropping this one; with none left, wait until the database is closed (it ends when the callback or engine call ends), or return an error naming the busy holder instead of Ok.
