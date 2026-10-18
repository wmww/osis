# Chat
> Summary: Scratch notes on how chat could work. Possibly stale: later design changes (claim keys, copy-not-handover, /seen heartbeat, etc.) were not re-checked against it. Rework when the owner asks to make chat fit the current design.

## Old proposal (under writer-stamped uploads; never reviewed by the owner)
The owner's hub pattern (participants as readers of the chat label, owning their messages) could not upload at blind nodes, since uploads needed the label's write key. This proposal worked around that.

A chat actor C: its admins write C's data (title, participant list, hidden-message markers), participants are read members of C. A messages group M, owned by C, with its own label. Each user has a per-chat participant actor P (owned by their person actor) that owns their messages and a group G_P listing them: P is a write member of M, M is a read member of P, and G_P is a subgroup of M. So M's actor reads every message (entitlement under M's label holds), every participant reads every message and edits only its own, and P's devices hold M's read and write secrets: they stamp uploads, send signals under M's label, and rotate M after a device loss. Messages keep the default `author` retention; its tokens derive from P's secrets, so no participant can delete another's at servers. Moderation: C's admins (admins of M by ownership) remove P from M, drop G_P from M's subgroups and delete P's entries with M's delete key; the removal rotates M's write key, so P cannot re-stamp, and other members drop the messages as outside their closure. Per-message hiding is a C-written marker; admins cannot edit or purge another owner's message. A link into the chat: K with write on M and read on C; the joiner invite-grants its P into K, then writes its own edges (M on P, G_P under M). Any M writer can vandalize M's `/group`; honest clients re-add their own G_P (a deterministic repair) and admins remove the vandal (authenticated malicious writers are bounded). Reactions and read markers live on the reactor's own participant things, since roles are per thing, not per aspect. Residue: participants only read C, so a lost device keeps reading C's data until a C writer next writes.

Open questions for the owner: whether participants writing M's `/group` (vandalism bounded by repair) is acceptable, and whether readers of C that cannot rotate C matters.

## Related
- Moderation is not deletion (notes/sync.md).
- Wake priority per chat is undecided (notes/networking.md, Priority).
- Timeline query shape (notes/api.md).
