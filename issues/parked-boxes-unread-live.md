# A parked pending commit's boxes are read at open but not when it parks
> Summary: `keys::read_all_pending` (the open's sweep) reads the boxes of every pending row, `PendingKind::Parked` ones included (they decode with `CommitBlob::decode`). Live, `park()` (core/engine/src/apply/mod.rs) never calls `read_pending_boxes`, so a fresh open holds reading-only secrets the live node does not. A parked commit is pending (spec/versioning.md §2), and every pending commit is a reading-only source (spec/crypto.md §4).
> Priority: normal
> Tags: engine, keys, tests

Reached by `pend_aside` with `Reason::Parked` first among the reasons, or by `late_parts` with Parked alone, where a decodable `secrets.0` part waits beside the parked part. Fix: `park` reads the boxes of what it stores when that decodes, as `decode_pending` does. Owed: a fixture with a parked part and a waiting `secrets.0` box part beside it, checked to fail without the fix (`check_index`'s fast pass catches it once reached).
