# A label stays open on a connection across a new step
> Summary: a server keeps a label opened (and subscribed) on a connection when a new step is registered (`ServerConnection::register` touches only the store), so a departed node that keeps its connection open keeps downloading the label at that server: it is pushed every new entry, reads what is wrapped under epochs it holds (the rotation commit that removed it, with its fresh deposit seed; stranded heartbeats; §4 exception copies), and sees the size and timing of everything else, for the life of the connection. The spec says nothing about opens at a new head.
> Tags: security, sync, proto

Severity: low (needs the departed node connected through the rotation; content under the new epoch stays unreadable).

Where: core/proto/src/server.rs (`opened`, `subs`, `register`); spec/sync.md §5 Open; the client's reaction to a head event (core/node/src/sync/inbound.rs `new_head`, open.rs).

Fix direction: at a new head the server ends the label's opens and subscriptions on every connection whose open was under another step's key (one head event pushed, then nothing; later requests answered 8 "not opened"); clients re-open on the head event (sync key if they hold the new epoch, else claim, which members listed in the set do in one round trip). For the remover's own rotation commit not to reach a still-open departed node first, it would also have to register before uploading that commit (today `reregister` sends Upload then Register, and the Upload is pushed to subscribers at once); spec/permissions.md §3 currently says upload first.
