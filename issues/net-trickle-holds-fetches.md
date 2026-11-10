# A co-reader trickling one reply holds every fetch on its connection
> Summary: The stall rule moves on any byte of a reply to the oldest request, so a hostile co-reader that sends one byte of a reply frame per stall time (frames up to `MAX_MESSAGE`) keeps the connection forever while answering nothing else: its stream Fetches stay out, and bodies other streams owe wait for it (`stream_settle_all` asks only bodies asked nowhere).
> Priority: normal
> Tags: security, node, sync

## The case
Only the oldest request must move (notes/flow-control.md, Stall), so later requests on that connection need never be answered while the oldest's reply trickles. Bounded in bytes (one reply frame), not in time: at a byte per ~2 min a 64 KiB frame lasts months. What it holds back at this node is still bounded (`MAX_WAITING`), but the writes it announced first stall here while an honest co-reader serves them. A peer that pushes at full speed while answering nothing is closed; this one is not.

## Directions
- Any rule where any link speed passes is defeated by trickling; a time bound needs a rate floor (a picked number: notes/arbitrary-values.md).
- Ask a second source for a body another stream owes while its fetch elsewhere is older than that stream's announcement (each body then crosses twice in a mesh; rejected so far for that cost, notes/peers.md).
