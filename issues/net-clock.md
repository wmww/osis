# A peer can pull a node's clock
> Summary: The clock offset is the median over all connections, peers included, with no cap, so one peer can set it; a node pulled 120 min behind fails its own `redeem` (`own commit not applicable`). Against "a wrong local clock harms only that node's own writes". Also LAN tags tolerate less skew than `MAX_DRIFT`. Audit rows 34, 35. Part of issues/net-rework.md.
> Priority: normal
> Tags: node, security

- Offset: conn.rs median over every connection; apply/mod.rs refuses the node's own commit (p10 in issues/no-server-audit.md: -120 min fails; +120, ±30, -5 fine).
- Fix: bound a peer's influence or need agreement from several sources, and never let the offset fail the node's own commit.
- LAN tags: 10-20 min tolerance against `MAX_DRIFT` 60 (row 34; see issues/net-connect.md, LAN rules), and a connection is what would correct the clock.

Unsure (design): what sources count (own nodes more than strangers?), and whether a node with no agreement keeps its own clock.
