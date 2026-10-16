# Blind server abuse limits and accounts
> Summary: Who may create labels on a blind server and store how much, without the server learning identities; how paying accounts tie to labels. Owner call (privacy tradeoff).
> Tags: sync, security, owner-call

Requirement (spec/requirements.md, untrusted nodes): a blind node can limit abuse without learning identities. Today servers only cap storage per label and rate-limit retires, wrap replacements and signals; anyone can register a new label.

Constraint found so far: an account credential must be presented to one server by an admin and bound to (server, label), never placed in the relayed `/label` chain, where every member and every server would see it.

Also open: abuse limits for free relaying and first-contact help on the official server (notes/networking.md).
