# Retain: an ended keyless grant still keeps a copy
> Summary: spec/permissions.md §3 Retain counts a live way only with key access, but an ended way saying retain by its role alone: a keyless grant (spec/crypto.md §4 Key access) removed saying retain keeps the node a copy of what it read nothing of. Reproducer `holding::repro_an_ended_keyless_grant_keeps_no_copy_spec_permissions_3`.
> Priority: normal
> Tags: security, engine, spec

- Shape (public API only): Bob grants Alice read on T0, mints T1 under T0, grants T1 read on T0 (keyless: T1's key derives from T0's) and Alice read on T1. Bob removes T1's grant saying retain, then removes Alice from T0 (no retain): Alice keeps a copy of T0 and still reads it.
- The rule should be one for both forms: a way through a grant with no key access keeps nothing. For an ended grant that means key access as it stood just before the write that last changed it (beside §3's "holding read or above on H just before"); engine `lost::ways` reads `Timeline::ended` for the role only, and `Timeline::keyless` covers standing grants only.
- The sync differential never writes retain, so it does not reach this.
