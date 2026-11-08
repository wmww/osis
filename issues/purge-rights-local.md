# A purge request without the right is written anyway
> Summary: `purge(Purge::Commit(..))` (and other purge requests) by a writer who may not purge what it names, by the aspect's purge set, is signed and sent though it drops nothing anywhere; rights are checked locally before signing for every other write (notes/api-design.md Standing rules). Refuse it with `Permission` at commit, then drop osis-chat's private `may_delete`.
> Priority: normal
> Tags: osis, api

- osis-chat refuses it itself (`may_delete` in `edit`/`delete`); any other app sends a request that does nothing, and its user sees no error.
- Judged at commit against the purge set of each named delta held here (spec/permissions.md §6); a named delta not held here can't be judged: say what happens then (write it, as a request naming a later-arriving delta is honored when it comes).
- An app could also ask before showing a delete button; with the refusal in osis that is a dry run or a rights read, not a second rule.
