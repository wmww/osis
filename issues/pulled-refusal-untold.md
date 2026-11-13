# A node pulling an entry refuses it without telling the source
> Summary: `unread_events` (node/sync/unread.rs) tells the source node only of cap and tombstone refusals of a pulled stamped entry; any other code from `serving::pulled` (a stamp its head keys refuse, expired, malformed) drops it silently. The source keeps it as lacking there (`at_source` `takes`), so its deletes at that peer wait (spec/sync.md §7 Role view first) until a head move re-shows it (`relog_for_head`) or a refetch; the source cannot tell a refusal from a slow pull.
> Priority: normal
> Tags: sync, node-sync

- Seen in sim `member_churn` 478483357567/478483357569: the peer refused a rotation commit for a stamp under keys it did not hold yet and fetched it again only minutes later. The minutes are the stall rule, not a bug: a blob counts as asked while one source's fetch of it is younger than `STALL_TIMEOUT_MS` (notes/node-sync.md), so a fetch out to a partitioned peer holds that blob for 2 min before the next source is asked.
- Fix shape: answer every refusal of a pulled entry with its code (as cap and tombstone are), and have the source treat a refused entry as not taken there until something it judges by changes (its stamp, or the peer's head).
