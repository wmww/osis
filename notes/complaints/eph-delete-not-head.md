# eph-delete-not-head
> Summary: a repro of one node's ephemeral delete passed without the fix, since other writer holders delete absorbed entries too.

- First repro passed with the fix disabled: the admin and another writer held the entries and deleted them themselves. Needed `ephemeral_bytes: 0` on every other writer to isolate. A demotion (write key only) did not refuse the delete either: writers' level deletes go under the sync key.
