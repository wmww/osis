# Departed members and leaked links keep depositing
> Summary: no flow refreshes an actor's deposit seed on a departure, and `refresh_deposit_seed` reaches servers only at the next rotation's step (`issue_step` ignores a changed deposit key). A removed member, or anyone holding a revoked or expired link's text (K's `/keys` with its deposit seed was readable through L), keeps deposit access to K's label, which is K's inbox, for good: they can keep its budget full (grants wait) and, with issues/inbox-copy-any-commit.md, get content copied in.
> Tags: security, engine, sync

Severity: low-medium (spec/crypto.md §3 makes the refresh a MAY; spec/requirements.md opens the budget only to "anyone who must reach the group's members").

Where: core/engine/src/flows/moving.rs:53 (`refresh_deposit_seed`, called by no flow); core/engine/src/flows/labels.rs:203 (`issue_step` returns `None` unless a role epoch is newer than the head, so a new deposit key is not registered until a rotation); core/engine/src/flows/links.rs `finalize_link` / `revoke_joiner` and `edges::demote_in` (no refresh).

Scenario: a link's text leaks; the sharer revokes the link. The leaker derived K's deposit seed from K's `/keys` while L could read it and keeps filling K's deposit budget, so the next redeemer's invite grant (a deposit) waits forever.

Fix direction: write a fresh deposit seed in the removal or finalization commit of an actor whose departed party could read its `/keys` (at least for links), and have `issue_step` issue a child when the head's deposit key differs from the one the current seed derives.
