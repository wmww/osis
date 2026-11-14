# A dial its driver never answers stalls that peer forever
> Summary: node sync waits on each `Action::Dial` until the driver reports `Up` or `Down`, with no bound of its own: while a dial is pending that peer is never dialed again. The driver in tree always answers (QUIC's handshake ends at its idle timeout, `link::dial` and `Close` abort the task), so only a driver bug or a transport whose connect can hang (a stuck DNS lookup, a new transport) stalls it. Cheap bound: on `Tick`, a dial pending past a limit is closed as if `Down` (`conn.rs::close` already emits `Action::Close` for a dial not up yet) and retried at the usual pause.
> Priority: low
> Tags: node-sync

- The limit must pass notes/arbitrary-values.md: at 0 no dial ever comes up; at infinity it is today's behaviour. Tying it to the transport's own give-up (`osis_transport::nat::DIAL_MS`, QUIC idle timeout) plus a margin keeps it from cutting a dial a working transport would finish.
- Tests that drive an offline node by hand use `Net::offline_handle`, which answers dials with `Down` (notes/testing.md).
