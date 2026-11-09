# The horizon must be the dropped-deletion position, not the oldest held deletion
> Summary: issues/net-reconnect.md set the horizon to the position of the oldest deletion event held, the log's end when none. Safe, but it makes a from-the-start reply out of nearly every reconnect on a log with no deletions or an old one (core/test/tla/net, SN_horizon). Rule: a durable position, the newest deletion event dropped.
> Priority: normal
> Tags: sync, node, proto

With no deletion held the horizon was the log's end, so every cursor below the end was "no cursor": each reconnect with any new event streamed the whole live set. With one held deletion, every cursor below it did. Nothing was gone; the model reports a needless from-the-start reply (`SN_horizon`, ReconnectCost).

## Rule
The horizon is the position of the newest deletion event the log has dropped, 0 if none, kept durably with the log. A cursor at or past it is honoured. issues/net-reconnect.md states this. It is one durable number, not a trim position sent on the wire.
