# Can a peer tell it is the same device reconnecting?
> Summary: Tess: to make a reconnect cheap, a peer must recognise that this connection is the same device of an account as last time (not which device, not its commits). Is that acceptable under "never which devices an account has"? Proposed: yes; the alternative is every reconnect costing a full first contact.
> Priority: normal
> Tags: tess-call, sync, node, spec

## Question
Is it OK that a node you sync with directly can tell "this is the same device of Alice's account that connected yesterday" (and so count how many of Alice's devices connect to it), when it still cannot tell which device, or which device wrote what?

## Trade-off
- **Yes (proposed)**: a reconnect sends only what changed (under 1 KB when idle, whatever the number of groups). The peer learns the count of the devices that connect to it directly. It learns this today from connections and listening keys; the record makes it durable. Which device wrote what stays hidden.
- **No**: nothing can link two connections of one device. Every reconnect is a first contact: every group's filter again (about 1.2 B per group and peer, 120 KB at 100k groups) and a listing of every shared group's entries, on every connection. A phone that reconnects often pays this constantly. A peer with two routes to one of your devices (LAN and relay) keeps both connections, since it cannot tell them from two devices.

## Why users care
Reconnecting is what phones do all day; the cost is per group. The privacy loss is only that someone you already share data with learns how many of your devices connect to them. If you say yes, the requirement sentence becomes "Readers learn which accounts take part, never which device made a change; a node you sync with directly can tell your devices apart as connections, not by anything they wrote."

## State
Designed as "yes" (issues/net-shared-set.md, issues/net-reconnect.md), not yet decided. Three things rest on it; with "no" each goes:
- **The record and the pair key** (issues/net-reconnect.md): r is per connection, nothing durable per peer. Every connection is a first contact: whole filters both ways and one listing of every shared sync ID's live entries (the stream from the start).
- **Cursors** (issues/net-reconnect.md, One node log): a cursor handed back on a later connection says "I am the device you gave this to". With "no" a node presents none, and every connection streams from the start.
- **Two connections to one device** (issues/net-connect.md Preferring the LAN; issues/net-reconnect.md Resume "two connections to one peer: one record"): a connection proves an account, not a device, so closing the duplicate route needs to know both go to one device. With "no" both stay (one per route per device; the closing of a sibling's connection by account would be wrong), and each is a first contact of its own.
