# A stamp fixed while its refused entry is in hand is never taken
> Summary: At a node keeping S unread, an entry refused for its stamp is `settled` for every message in hand; a later push carrying the same entry under a good stamp, arriving while the refusing message waits, is passed over as settled and applies without it. Nothing announces it again, so the node never takes it.
> Priority: normal
> Tags: sync

Found writing `streams::a_refusal_told_before_an_earlier_apply_stands_for_the_report_spec_sync_streams_4`, not tested yet.

Steps (core/sync/tests/it/streams.rs, `Pair::kept()`): b holds a's push of y in hand (b's Fetch of y held back); a sends x under a bad stamp (b refuses it at `stage`, code 1, and `Pulling::settled` takes (S, x)); a stamps x well (`Store::take_stamp`), and its push announces x without bytes (inlined once already). `fetch` drops x from the queue as settled, the push's owed x counts ready, and once y comes all three apply. b never holds x; a's refusal ended with the new offer, so a waits on nothing either.

Rule it breaks: spec/sync-streams.md §4 Refused (a new stamp goes as its own event and is judged as such) and Flow control (an announcement is kept until its entry is taken or no longer wanted). `settled` holds a body's outcome, but a refusal for a stamp is the outcome of that announcement, not of the blob: a fix keys it by what was judged (the stamp), or drops a refused entry from `settled` when a later message in hand announces it otherwise.
