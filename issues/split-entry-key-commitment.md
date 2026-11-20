# Split entries commit to no key
> Summary: XChaCha20-Poly1305 commits to no key, so a writer can seal a split commit's path entry to open under two path keys of its choosing, to two different plaintexts, and hand each key to different encryptions of the thing's parts; a thing's stated path is then not one fact. Harmless while no part is judged along its path (Interim); must be closed before step 3 reads paths.
> Priority: normal
> Tags: security, commit, engine

spec/wire.md §4 `Split`: an entry is XChaCha20-Poly1305 under the thing's path key; every encryption of the thing's parts carries a key, and the writer may use any key (a fresh random one where it holds no roles secret). Poly1305 is linear in the ciphertext blocks, so a writer picking two keys solves one equation over its field for one 16-byte block and gets an entry opening under both (`engine` `validity::entry_under_two_keys`, about a thousand tries). With four listed tids as freedom, both plaintexts can also be well-formed lists (a grind of about 2^40 for the structure bytes under the second key).

What it does today (`validity::an_entry_opening_under_two_keys_judges_alike_in_any_order_spec_wire_4`): a path under one key and no list under the other. A reader holding only the second encryption holds D's parts as nothing, like a copy whose parts miss their hash, until the first comes; holding both in any order applies D. The spec's "an entry ... leaves T's parts holding nothing at every reader of T alike" is so true only of what the readers hold, not of the commit.

What breaks at step 3 (judging each part along its stated path): two well-formed paths, one a held chain and one not; each encryption's parts judged along a different path, and the engine keeps one key per (commit, thing) (`CommitBlob::keys`, `merge_parts`: the last taken), so the verdict turns on arrival order.

Fix (one of): a key-committing entry (a 32-byte commitment of the key beside the ciphertext, `kdf("path commit", key)`, about 32 B an entry; or the padding fix, 32 zero bytes leading the plaintext, also 32 B), or the path key fixed by the header (no random fallback; every key derived from a roles secret, the derivation checked by the reader: a reader without the roles secret cannot check it, so this alone does not do). The first is one rule for every reader.
