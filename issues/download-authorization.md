# Download authorization at blind nodes
> Summary: Blind nodes currently serve any label to anyone who knows its ID; the proposal gates downloads by the label's upload key, which needs a bootstrap for new members. Owner to confirm.
> Tags: sync, security, owner-call

Without gating, a revoked link or removed member keeps fetching from blind nodes, and a stranger who learns a label ID can count its blobs.

Proposal (notes/sync.md): the upload key also authorizes downloads, re-registered eagerly like the others. Consequences: keyless nodes never pull, so server-to-server replication is driven by a key holder or a mirror given the upload private key alone.

Bootstrap: a new member cannot derive the key before it holds the read secret, which sits in a `/secrets` box under that very label. Proposed: the grant also goes under a label the grantee already reads (certificate copy) or as a delivery blob under its contact label (spec/sync.md §3, Grant delivery). The recovery card's bootstrap label exists for the same reason.

To decide: adopt gating; exact download message and signature; whether bin listing and specific-blob fetch use the same key.
