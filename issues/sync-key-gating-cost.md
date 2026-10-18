# Is sync-key download gating worth mailboxes?
> Summary: Gating downloads by the current sync key is what makes mailboxes, delivery blobs, mailbox deposit budgets, the `stale` path and the missed-rotation lockout necessary. Owner keeps gating (ex-members must fetch nothing, new or old). Two viable replacements for mailboxes: claim hashes in the registration step, with the registrar's key implicit or ephemeral.
> Tags: owner-call, sync, security

## What gating buys
An ex-member (or anyone who learned a label ID) cannot keep fetching ciphertext at an honest blind server once an admin has registered the new step: no counts, timing or deletions, no laggards' old-epoch wraps (content), no harvest of new ciphertext against a future key break (notes/sync.md, Reads gated by the sync key). Limits it already has: member peers authenticate members directly, so it acts only at blind servers; a writer's rotation leaves the old sync key registered until an admin of that actor syncs; tension 7 (dishonest server) is untouched.

## What mailboxes cost
Every actor needs a mailbox (`/keys` names it; key actors derive theirs from the seed); every rotation delivers one boxed-twice projection per member (about 2.5 KB per member per rotated actor, spread over mailbox servers); mailboxes have deposit budgets that can overflow (issues/mailbox-overflow.md); clients need the `stale` reply and the mailbox-first bootstrap; a member that missed a rotation is locked out until a member delivers or syncs P2P (tension 29); deposits made over one connection link recipients' mailboxes at a shared server; a key actor's mailbox is a stable per-device label, so its server can count a person's devices.

## The crux
A laggard and an ex-member hold the same label keys, so the gate needs something only the laggard has: its own KEM private key. Mailboxes reach it by delivering a box to a per-member label. The alternatives below let the server check it directly, without learning who the member is.

## Alternative 1: claims in the registration step (owner: viable)
- A registration step carries a **claim set**: per current reader M of the label, `h_M = BLAKE3(kdf("label claim", DH(registrar X25519 priv, M's X25519 pub), label ID || seq))`, padded with random hashes to a power of two. It replaces the previous step's set.
- **Claim** op: a client answered `stale` sends candidate tokens; the server opens the label on the connection if a hash matches, else refuses exactly as it refuses a stale open. No burn: a person's devices share the person's token.
- The member then downloads the rotation, derives the new sync key; the claim is bootstrap only.
- Who claims with what: persons and teams with their read-role X25519 key (members derive it from the read secret); devices with their node key on the person's home label; the recovery key with its seed key (card unchanged); a link key with an X25519 key derived from its seed (new; L has no KEM key today) on K's label.
- An ex-member computes no token (needs M's or the registrar's private key). The registrar's key is never held by an ex-member because the registrar must already hold every keyset change the removal caused (the epoch-covers rule, spec/crypto.md §4).
- Removes: key-actor mailboxes, rotation deliveries, deposits for deliveries, mailbox overflow, the mailbox-first bootstrap chain, tension 29 (down to the residue below), the per-device stable label, the deposit linkage leak. `/keys` keeps naming an inbox label for grants and hand-overs from actors the grantee shares no label with (the former contact label); its own writers drain it, so overflow is tension-17 flooding.
- Costs: the server learns the read-roster bucket per label and how many members returned late per epoch; about 1 KB per step at 64 readers; the gate is classical (a quantum ex-member could compute claims and fetch hybrid-protected ciphertext).

### 1a: registrar key implicit
The registrar uses its own actor's current read-role X25519 key (a device: its node key). The member guesses: known admins' keysets × a few seq values, sent in one batch. Nothing is fetchable before a successful claim, so an ex-member learns nothing, not even that a rotation happened. Residue: a registrar the member never heard of (new admin, or an admin keyset the member missed) leaves it on P2P or a later step.

### 1b: registrar key ephemeral in the step
The registrar puts a fresh X25519 public key in the step and uses it for every DH; the chain stays fetchable by anyone. No guessing, one DH per candidate seq. Cost: anyone with the label ID can poll the chain and watch rotation timing and roster bucket forever. PQ option exists only here: ML-KEM ciphertexts per member in the step instead of DH (about 1.1 KB per member per step).

## Alternative 2: no gating against ex-members (owner: rejected)
Reads accept any sync key of the registration chain; upload, deposit relay, delete and signal send need the current one. Kept for the record: download-before-upload closes most of the laggard-wrap leak; a step listing skipped epochs' sync keys covers grantees boxed under an unregistered writer epoch; the recovery card would carry a sync key. Loses: ex-members watch label activity and harvest new ciphertext forever.
