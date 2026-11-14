# A reader demoted to sync drops its copy
> Summary: Lost access keeps the sync secret of an actor the node still holds sync on (`rotation/lost.rs:493`), then `forget` erases the group and its labels and `forget_records` drops the hub store's rows of each (`retention/forget.rs:233-252`, `sync/state.rs:2444`, `HostStore::reader_forget`). The node keeps the sync role and secret but no ciphertext and serves nothing, against spec/permissions.md §3 (a sync holder keeps its sync secrets) and spec/requirements.md (a node that cannot read data may hold its only copy).
> Priority: normal
> Tags: node, engine, host

Found by reading (notes/cannot-read-audit.md); no test covers read→sync demotion (inbox_life covers a sync grant, unread.rs an outright removal). The read rows should move to the unread set (the hub's rules, its caps counting them) instead of being shredded; plaintext and read state go as now. Related: issues/unsynced-label-rows-kept.md (the other read→not-read transition).
