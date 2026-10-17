# Read revocation after device loss, and rotation policy
> Summary: A lost device keeps reading every actor its person is a non-admin member of until that actor's admins rotate; spec/permissions.md §3 requires the rotation but only admins may do it. Proposal: writers rotate roles up to their own. Also open: a rotation policy for forward secrecy and healing (scheduled epochs, no-history joins, device KEM rotation). Owner call.
> Tags: security, permissions, crypto, owner-call

Found by the chat deep dive. A blind node cannot stop serving a device (ephemeral connection keys; downloads are not tied to members, issues/download-authorization.md), so re-keying is the only read cut-off osis has.

## Who may rotate
Alice removes her stolen phone from her person actor: its write authority ends at once (timeline). But the phone holds the current read secret of every actor Alice is a member of, and new content is wrapped under that secret until it rotates. `/secrets` is admin-only (spec/permissions.md §1), so in the chat pattern (participants are readers of the chat actor) neither Alice nor the next message writer may rotate; only chat admins can. In a 1:1 chat under the per-author pattern it is Bob's participant actor that has to rotate, since Bob owns Bob's messages.

spec/permissions.md §3 already says a removal rotates every actor above the removed member whose secrets it could open, which includes the chat; nobody but the chat's admins is allowed to. Nothing leaks until the next write, so the rotation only has to happen before that write. Concurrent rotations are no longer a problem (epoch forks, spec/crypto.md §4), so many members rotating at once is fine. Proposal:
- Allow a member with role r to rotate the secrets of roles ≤ r (writers rotate read and write secrets). Not readers: a reader sealing a new secret to an incomplete roster would lock members out, a power beyond "waste storage" (spec/requirements.md).
- Client rule: before the first write under a label after observing a co-member's device removal (the removal certificate is relayed under shared labels), rotate and seal to the current roster. A writer cannot re-register the label (steps are signed by the admin-derived delete key), so the upload key stays until an admin rotates; harmless for reads, since new wraps use the new read secret.
- The chat pattern then either makes participants writers of the chat actor (they can also edit its data) or keeps them readers and relies on admins' clients auto-rotating. Owner to pick.

Residue either way: a member that has not yet heard of the removal still wraps under the old epoch, and the thief reads that message. Signal has the same shape with sender keys; its server cut-off covers everyone on top.

## Rotation policy (forward secrecy and healing)
A compromised member device yields the whole stored history of every actor it reads, since the current read secret opens all older epochs through the history boxes (spec/crypto.md §4). That is the price of shared history and is accepted, but the primitives for mitigation exist without any policy:
- Scheduled epoch rotation (Megolm-style, weekly), so a compromise exposes bounded future content once healed.
- A rotation variant that writes no history box, so a member joining after it reads nothing earlier ("no history for new members"). Existing members keep old epochs locally; their new devices would need a device-to-device transfer, as in Signal.
- Periodic rotation of device KEM keys (`/keys`, already rotatable), so a stolen person secret stops opening new boxes once the person has re-sealed: the healing step.
Decide which are core policies, which are app choices, and the costs (1.2 KB per member per rotation).
