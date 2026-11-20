# Blob and section wraps commit to no key
> Summary: A blob's wrap and a section's wrap are XChaCha20-Poly1305 under a key derived from one of several epochs' secrets, and a reader takes the first that unwraps; a writer can make one wrap open under two epochs to two keys, so an entry or blob reads as the commit to holders of one epoch and as junk (Bad, dropped) to holders of another, a holder of both reading the junk. Contents stay self-authenticating (no two readers read two different commits); what breaks is that reading more secrets never reads less.
> Priority: low
> Tags: security, engine, crypto

Every AEAD use and what binds its plaintext (the path entry, which bound nothing, commits to its key: spec/crypto.md §5 Path entry):

| use | key chosen by | two honest recipients, two keys for one ciphertext? | what binds the plaintext |
|---|---|---|---|
| blob ciphertext | the writer (fresh blob key) | yes, through its wraps (below) | a commit blob: the signed header, parts by delta hash, path keys by entry commitment; record blobs by tid, list blobs by `list_root`, chunks, nodes and pages by link content hash |
| blob wrap (per sync ID S) | the logger; key from a read (or roles) secret of S's thing | yes: holders of different epochs of S's thing | nothing: blob key and order |
| section wrap | the writer; key from a read (or roles) secret of the thing, or the blob key | yes: holders of different epochs | nothing: the section key |
| section ciphertext | the writer (fresh section key) | yes, through its wrap | parts by the header's delta hash; path keys by entry commitment |
| path entry | the writer | yes: roles secret, sections, copies, header-only copy | its key commitment (built) |
| inner seal | the account's node; key per epoch | one seal per epoch | the opened node signature verifies over the commit ID: only nodes whose keys the writer holds |
| rotation's sealed devices | the account's node; one epoch's inner secret | no: one key | (one key) |
| sealed box, joint box layers, sealed fire, entry box | KEM to one public key | no | (one key; the KEM key binds its ciphertexts) |
| symmetric box wrap, history box | one epoch's secret, named in the AD | no | (one key) |
| store pages, node log | the node itself | no | local |

Smallest attack (blob wrap): a writer of S holding S's thing's read epochs e1 and e2 logs a blob X under S with one wrap that opens under `kdf("wrap", e1)` to blob key k1 and under `kdf("wrap", e2)` to k2, X opening under k1 to its commit C and under k2 to junk (one Poly1305 block solved for; `validity::entry_under_two_keys` builds the same for a path entry). A reader tries its secrets newest first (`osis_blob::unwrap_any`), so every holder of e2 opens X to junk, marks it Bad and does not keep it (`streams::pull`, `store::follow::open_held`), while a holder of e1 alone (unboxed at e2, spec/crypto.md §4 Low floor) applies C. The same at a section (`Section::open` takes the first secret that unwraps; a junk section is bad input for the whole blob).

Effects: S's readers disagree on whether entry X holds C, by which epochs they hold, not by what entries they hold. Contents never diverge (C is signed; the junk side holds nothing), so the writer gains only a withholding it could not otherwise aim (without the trick a holder of more epochs reads at least what one of fewer reads).

Fix (one of): a reader tries every held secret until one unwraps to a blob (or section) that opens and decodes, so reading is monotone in held secrets (one rule, no bytes); or a key commitment in each wrap (32 B a wrap: 57 to 89, and 72 to 104 a section).
