# Blind server abuse limits and accounts
> Summary: Who may create labels on a blind server and store how much, without the server learning identities; how paying accounts tie to labels; whether per-member rate limiting is possible without identifying members. Owner call (privacy tradeoff).
> Tags: sync, security, owner-call

Requirement (spec/requirements.md, untrusted nodes): a blind node can limit abuse without learning identities. Today servers only cap storage per label and rate-limit retires, wrap replacements and signals; anyone can register a new label.

Constraint found so far: an account credential must be presented to one server by an admin and bound to (server, label), never placed in the relayed `/label` chain, where every member and every server would see it.

Also open: abuse limits for free relaying and first-contact help on the official server (notes/networking.md).

## Per-member rate limiting
Chat makes tension 17 concrete: any participant (a reader of the chat label) can fill the label's storage cap with junk the server cannot tell from messages, and admins only notice after the fact. Per-member limits need the server to tell members apart, which is exactly what it must not learn. Options:
- Per-label pseudonymous member keys: an admin certifies (label, pseudonym public key) with the hard-delete key; uploads are signed by the pseudonym. The server then links one member's uploads across sessions (author structure, though not identity), which the requirements forbid.
- Rate-limited anonymous credentials (what Signal's zkgroup does): unlinkable, but algebraic-MAC or BBS-class zero-knowledge crypto, far outside the simple-Rust suite.
- Stay with per-label caps, per-connection rate limits and admin hard-delete; accept the junk window.
None is free; the owner should pick.
