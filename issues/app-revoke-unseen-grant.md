# A removal that sees a placement but not its grant leaves the thing shared
> Summary: Placing a thing into a shared tag and granting the tag are separate commits on separate labels. A device that has the placement but not the grant, and takes the thing out of the tag, queues no revocation (no live edge there); when the grant arrives it stands, and the tag's members reach a thing the user took out.
> Tags: core-ask, app, permissions, security

Repro: `app/tests/it/share.rs` `removal_missing_a_later_grant` (ignored): one device has taken the access back, the other (not aware) re-tags and grants again, the first sees the placement only and the user removes the thing again.

- Any grant does this: a confirmed share (`add_tag`), `add_tag`'s re-grant while an entry waits. Core's later-removal-wins rule only helps when a removal is written at all; here none is, because the remover's view shows no edge.
- Core's pre-sync does not help: nothing is demoted. The window is the time between the other device uploading the placement and the grant (longer if it goes offline in between).
- Fix directions: queue (thing, tag) on every removal even without a live edge, and keep the entry (with the removal's time) until a later grant or re-placement makes it moot; then an edge with `since` before the removal on a thing not under the tag is taken back when it arrives. Or write placement and grant in one commit (they are on different things and labels; needs core support). A sweep of every tag edge on things not under the tag would also revoke fresh shares whose placement has not arrived yet, so it is not a fix by itself.
