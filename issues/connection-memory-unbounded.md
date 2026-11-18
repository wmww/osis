# Memory for open connections grows with the number of peers
> Summary: spec/requirements.md Scale: peer input never causes unbounded allocation. A node's memory for open connections grows with how many peers are connected, and it sheds none when memory runs low.
> Priority: normal
> Tags: sync, transport, security

Wanted: a bound on what connections may hold in all, with a defined outcome past it (which connection goes, how it is told), passing notes/arbitrary-values.md.
