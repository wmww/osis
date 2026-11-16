# A thing kept unread through a ticket stays entered on the ticket's word
> Summary: A sync-only grantee whose account files the thing by its ticket keeps S unread (`thing_sync` is `Unread`), but the node closure holds the thing only as `Ctx::Ticket`: it holds no role commits it can read, so it never becomes keyed and never enters as `Ctx::Unread`; `closure_holds` is false and a closing head has no `Unread` edge to take out.
> Priority: normal
> Tags: sync, engine, tests

- Seen in osis-sync `destruction::three` (differential world, `Grant(0, 0, 1, Gives::Syncs)` then accept): node 1's store keeps S, `thing_sync(t)` is `Unread([S])`, `closure_holds(t)` false.
- `destruction::a_closing_head_takes_a_kept_thing_out_spec_sync_judgement_6` is ignored for it (it fails on its first line, "node 1 keeps t"). `destruction::a_destroyed_things_sync_id_empties_but_its_request_past_its_window_spec_sync_judgement_5` ("node 1 lost the request") may share the cause.
- Question: spec/sync-set.md §2 enters a thing without own keys on the ticket's word until its role commits make it keyed; a node keeping S unread never reads them. Either a held sync secret of the thing (a sync-only grant's box) makes it keyed for the walk (entered `Unread`), or closes act on ticket-entered things too.
