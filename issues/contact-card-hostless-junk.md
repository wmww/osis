# osis: contact_card on a hostless store leaves a thing behind at each try
> Summary: `Osis::contact_card` (and so `profile()`) writes the profile thing and its group, then fails on `make_link` ("this database has no hosts"): every call on a hostless store adds 3 commits and an orphan thing. Check hosts first, or make it all-or-nothing.
> Tags: osis

Seen from osis-app, whose name field read `profile()` at each render (it now skips the profile without hosts, `app/src/chat.rs` `profile`). `contact_card` makes P (`write_with`), persists it, gives secrets and creates P's label before `make_link` refuses for want of hosts; the record that would make later calls return the same card is written only after that, so the next call makes another P.
