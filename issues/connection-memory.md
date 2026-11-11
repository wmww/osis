# Slow readers can hold a full hub
> Summary: while the hub is full (`max_buffered_bytes` unread), served input waits for readers to drain it and only output that does not move is closed for; readers that take a little each report period (16 KiB/s) and together hold the bound keep every served connection's input waiting until they drained it.
> Priority: normal
> Tags: security, node, tess-call

## The case
The design (notes/serving.md, Connection memory): past the bound the node reads no input and pushes nothing until readers drain, and closes only connections the transport took nothing of in a report period (`PUSH_POLL_MS`, one `WRITE_CHUNK`). About 15 connections sharing one group (a public link) that each pull a full request window (about 34 MiB) and then read at 16 KiB/s keep the hub full for about half an hour, and do it again once drained: served input waits that long, and peers whose requests wait past `STALL_TIMEOUT_MS` close their connections. A slow honest reader and such a trickler look the same.

## Options
- Accept it as a stated limit (now).
- Judge "moving" against what a connection holds: closed while full when at its pace it would not drain its holding within `STALL_TIMEOUT_MS` (a 34 MiB holder needs about 290 KB/s). Bounds the wait at the stall time, closes slow honest readers under load again.
- Close the biggest holder once the hub stayed full for `STALL_TIMEOUT_MS` (the wait could not be longer without peers' own stall timers closing anyway). Bounds the wait; the trickle attack still stalls the node up to 2 min per round.
