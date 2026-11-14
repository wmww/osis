# A boxes payload carries its author's whole rotation line
> Summary: Every boxes payload carries the author account's header-only rotations from its first epoch (spec/wire.md §9 position 8): about 1.5 KB each, so a payload's size grows with the account's age, and past `MAX_ROTATIONS` (256) the account sends no boxes payload at all, so its sync holders get no new sync secret at a rotation and lose the thing.
> Priority: normal
> Tags: sync, engine, label

- Cost: every rotation of a thing sends each sync holder a payload, so a thing with h sync holders rotated by an account with r rotations sends about h × r × 1.5 KB: work in the account's history, not in the change.
- Cliff: `Engine::author_proof` returns `None` past 256 and `boxes_blob` sends nothing. No rule recovers.
- Who needs the line: only a recipient that takes the payload whole (accepted, stamped, connected) and holds no chain of the author. A listing alone gives sync secrets only, which a forger's self-made key actor gets past anyway (it verifies), so verifying there protects nothing.
- Proposal: a listing alone takes a payload's sync secrets unverified, as before (a signature failing under a key held here still refuses it); the key for a whole take is the held rotation when held, else the carried line; the sender carries the line only in a grant's payload (an edge write naming the recipient), none in a rotation's or re-seal's, and past `MAX_ROTATIONS` sends the grant's payload without it (it verifies only where the chain is held, e.g. after importing the author's contact card, which carries its rotations).
