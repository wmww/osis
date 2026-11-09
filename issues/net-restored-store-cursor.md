# A restored or copied store honours cursors from a history it does not have
> Summary: A store cannot detect its own restore, so "a fresh log ID at restore" cannot happen. A cursor issued by the lost store opens on the restored one and silently skips what the new log writes at those positions (core/test/tla/net, SN_inc, SN_copies). Rule: every store start is a new incarnation; a cursor is honoured only on the store's own history.
> Priority: normal
> Tags: sync, node, spec, security

A store restored from a backup (or a copy running beside the original, or a crash that loses an unsynced tail) keeps the log ID and AEAD key. The peer's cursor still opens; the position exists; the events at it are different ones. The peer pulls after that position and never gets what the restored store wrote below it: `Synced` true, data missing (`SN_inc`, `SN_copies`, CaughtUpHolds).

## Rule
Every start of a store draws a new incarnation, as spec/crdt.md §2.1 does for sessions, and records the end position of the one before. A cursor carries (log ID, incarnation, position) and is honoured only if that incarnation is on this store's own history at that position. A restored copy's next start ends the old incarnation at the copy's position: a later cursor from the lost store is past it, a cursor from the sibling copy names an unknown incarnation; both are "no cursor", so a from-the-start reply. No detection of the restore is needed, and an ordinary restart costs nothing. The list of incarnations is bounded (a picked number, resource bound: 0 makes every restart a first contact, infinity is disk; an older cursor is "no cursor").

The pair key in a restored copy needs nothing further: `S_copies` passes with two live copies on one r. issues/net-reconnect.md states this.
