# Download authorization at blind nodes
> Summary: Blind nodes serve any label to anyone who knows its ID. Gating downloads by the label's upload key locks members out after every rotation they missed (they hold only the old key), so it needs a rotation-delivery path; without gating, ex-members keep fetching ciphertext. Owner call.
> Tags: sync, security, owner-call

Without gating, a revoked link or removed member keeps fetching from blind nodes (old content it could read anyway, new blobs it cannot open except laggards' old-epoch wraps, and volume and timing), and anyone who learns a label ID can count its blobs.

Proposal so far: the upload key also authorizes downloads (a signature over label ID and a connection-bound server challenge, once per connection and label; same for specific-blob fetch and subscriptions). New members are covered: a grantee finds its grant under a label it already reads or as a delivery blob under its contact label (spec/sync.md §3); the recovery card has its bootstrap label.

Problem found: every rotation re-registers the label, and a member that was offline holds only the old upload key, so it cannot download the commit carrying its new box. Offline members returning after a rotation are the normal case (a laptop away for a week while a stolen phone is removed), and a blind node is often the only path. Accepting the previous step's key only moves the problem to two missed rotations; accepting any old key is no gating for ex-members.

Options:
- **No gating** (recommended for now). Widens tension 7 from "an ex-member plus a dishonest untrusted node" to "an ex-member and any untrusted node" for old content and laggard wraps; strangers need the label ID, which only members, link holders and servers see.
- **Gating plus rotation delivery**: every rotation also places each member's boxes where that member can still download, e.g. a delivery blob under the member's contact label (needs the rotator to hold every member's card) or, for a person's own devices, the recovery bootstrap label (never rotates). About one delivery blob per member per rotation, on top of tension 21.
- **Gating by a non-rotating download key** (from the genesis secrets): blocks only strangers who learn an ID, not ex-members. Little value.
