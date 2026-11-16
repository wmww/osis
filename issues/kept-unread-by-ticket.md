# A close of a kept-unread sync ID does not survive the sync ID's stop
> Summary: A closing head takes a thing kept unread out of the node closure (`closed_kept` reads the store's path), but once `leave` stops S it shreds S's path too, so at the next walk (a restart) the held ticket's sync secret enters the thing kept unread again.
> Priority: normal
> Tags: sync, engine, tests

- `Store::shred` erases the path (`path::erase`) with the entries; `closed_kept` then finds no closing head while the ticket naming S is held, and the thing enters `Ctx::Unread` again. notes/node-closure.md says the store keeps the path while such a ticket is held; nothing does.
- Repro: osis-sync `destruction::a_closing_head_takes_a_kept_thing_out_spec_sync_judgement_6`, then `PowerOff(1), PowerOn(1), Run`: node 1 holds t again.
- Needed: S's closed path kept while a held ticket for one of its things names S, and gone with the last such ticket (leave knows no ticket by sync ID today), with no standing marker past that.
- `destruction::a_destroyed_things_sync_id_empties_but_its_request_past_its_window_spec_sync_judgement_5` ("node 1 lost the request") fails the same with node 1 entered kept unread or on the ticket's word: a different cause, unstudied.
