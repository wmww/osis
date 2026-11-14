# A crossed Lost lost with its connection leaves a rejoin too late
> Summary: when both sides end a member and the peer's answering Lost is lost (connection drop, crash, failed step), digests agree and the member rejoins from where this side's stream held it, past the peer's `until`.
> Priority: normal
> Tags: opens, streams

spec/sync-opens.md §6: B ends member S with `until` u_B and serves S only up to u_B, while A's stream position P moves past it on other members. A closes S itself (its own ending reached) with a Lost, keeping its rejoin as its stream held it (P). B, ending S, answers with its own Lost naming u_B, which A keeps as S's rejoin. If that answer is lost with the connection (or A crashes or fails the step that took it), both records lack S, the next digest matches, and A rejoins S from P: S's events at B in (u_B, P] are never served to A until some listing from the start. "One lost with its connection is found by the next digest" holds only when the member sets differ.

The deferred opens write (records flushed at the step's end) is no worse than the wire: the window is the same step. The fix is a protocol rule, e.g. a member this side closes while the peer may be ending it rejoins from the start unless the peer's Lost names a position (a brute-force rejoin on a rare path), or the peer keeps "where S stopped for that record" and serves a join named past it from there.
