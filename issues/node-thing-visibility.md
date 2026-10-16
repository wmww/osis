# Who can read a node's thing, and how a device enrolls
> Summary: A node owns itself, so without an edge nobody can read its `/keys` or `/node`, which breaks sealing secrets to devices, reachability and the all-nodes predicate; enrollment flow and cross-actor visibility of node things are unspecified.
> Tags: permissions, networking, crypto

Review 2026-10-16. Proposal recorded in notes/permissions.md (Nodes as things): at enrollment the node grants its person actor admin on its own thing; enrollment is a link redeem or pairing flow; the owner's key grants the first device.

Still open: collaborators must read `/node` of a person's devices to dial them (notes/networking.md decision 4) and the all-nodes predicate reads every member's nodes (notes/ephemeral.md). Candidate: a devices group per person, readable by its contacts (contact label, notes/crypto.md). Decide with the first-contact invite format (plans/protocol-spec.md item 10).
