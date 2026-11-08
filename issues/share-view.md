# Who holds a thing, as people and links
> Summary: osis cannot tell an app which of a thing's holders are people and which are links, so osis-chat's `participants`, `links` and `leave` read it from the roster's shape (a link's actor K, its key L, an account's nodes); design what `holders` says about each actor, then move those three into osis or the caller.
> Priority: normal
> Tags: api, osis, chat

- `holders(target)` lists every actor holding through grants: an account's nodes and recovery key, a link's actor K and its key L, joiners through K, teams. A share view wants the people (accounts, teams, joiners at the lesser role) and the links; a leave wants every way in that exists only for this target (a link's K, not a team).
- Only the maker knows its links (`links()`, from its seed thing). Every other node sees K as an actor holding the target, and after a single-use redemption L is gone from K's roster, so nothing durable marks K as a link's actor (spec/permissions.md §7 defines K by L).
- osis-chat meanwhile: an actor is read through when one of its holders has holders of its own (an account's holders are key actors nobody holds); L is K's holder with `may_grant` that nobody holds; `leave` leaves every actor the account holds the chat through. Teams are read through and left too, which is wrong for a team.
- Options: K's creation carries a marker (an aspect on K, so every holder can tell); or `holders` stops at key actors and names link actors. Then `leave(me, target)` can end a link join itself.
- Beside it: a purge request the requester may not make (by the delta's purge set) drops nothing anywhere and is still written; osis-chat refuses it locally (`may_delete`). `Purge::Commit` of a held delta could be refused `Permission` at commit, as rights are checked locally for every other write, and an app could ask before showing a delete button.
