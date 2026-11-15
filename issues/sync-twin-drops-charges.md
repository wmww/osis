# A twinned record's drop removes entries the survivor brought too
> Summary: `Opens::settle_pair` drops a twinned connection's record at the next `flush` (`Store::write_records` -> `gone_durable`), removing every unstamped entry charged to it untombed. An unstamped duplicate keeps its first bringer's charge (`Store::log`: `charged: old.charged`), so an entry both connections brought while S was open on both is removed though the survivor's stream already passed it: it does not come again on that connection.
> Priority: normal
> Tags: sync

Window: the Twin round trip after crossed first dials (spec/sync-opens.md §1 Twin), with S open on both connections and an unstamped carrier (a pending commit's) arriving on the loser first. The re-mark only reopens S where it was not open.

The same holds wherever a source goes while another holds a duplicate charged to it (a record evicted, a recordless connection closing); Twin makes it a same-peer, live-connection case.

Fix options: at a twinned drop, move the loser's charges (`CHARGED`/`BROUGHT` rows, memory charges) to the survivor's record instead of removing them; or charge a duplicate to every bringer.
