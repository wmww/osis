# dogfood-filing
- `Osis::create` overwrote D's group.0 with an empty group, silently undoing what `create_account` listed (synced group, profile); found only because the host's own profile showed up in `invitations`. "Home stays under it" is unbuilt (issues/sync-unbuilt.md), so nothing refused that write.
- The CLI harness has no network, so cross-account CLI flows can only be tested at the library (osis-chat) with the commands checked for parsing and exit codes.
- The brief's scratch dir must be made before a backgrounded redirect into it: the first run wrote nothing and reported exit 0 from the wrapper.
