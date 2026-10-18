# Is sync-key download gating worth mailboxes?
> Summary: Gating downloads by the current sync key is what makes mailboxes, delivery blobs, mailbox deposit budgets, the `stale` path and the missed-rotation lockout necessary. The owner decided for gating; the full cost is now visible and deserves a second look.
> Tags: owner-call, sync, security

## What gating buys
An ex-member (or anyone who learned a label ID) cannot keep fetching ciphertext: no counts, timing, laggards' old-epoch wraps, no wider surface against a future key break (notes/sync.md, Reads gated by the sync key).

## What it costs
Every actor needs a mailbox (`/keys` names it; key actors derive theirs from the seed); every rotation delivers one boxed-twice projection per member (about 2.5 KB per member per rotated actor, spread over mailbox servers); mailboxes have deposit budgets that can overflow (issues/mailbox-overflow.md); clients need the `stale` reply and the mailbox-first bootstrap; a member that missed a rotation is locked out until a member delivers or syncs P2P (tension 29); deposits made over one connection link recipients' mailboxes at a shared server.

## Alternative
Gate by any key of the label's registration chain (old sync keys keep serving). A rotation commit then reaches every member under the label itself (the old read secret downloads it, the new box opens it). Mailboxes shrink to the bootstrap cases that need them anyway (recovery card, contact card, first grant into a label the grantee cannot yet open). The old key then serves old and new ciphertext to ex-members; what they learn is counts, timing and (tension 7) the content of laggards' old-epoch wraps.
