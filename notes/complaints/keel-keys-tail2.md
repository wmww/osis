# keel-keys-tail2
- Removing the "read in no section passes" exemption broke 69 engine tests: LocalPeer's plaintext delivery recorded no opening, so every test compacting another's write relied on the exemption. The harness hid the production path (sealed fires) that leaked.
- The sync harness introduces every account as a contact, so chain-certificate gaps for history-less grantees cannot show there.
- An accidental `git stash list` in a compound command got the whole call denied; keep read-only git out of long chains.
