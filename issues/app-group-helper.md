# Per-account app groups: every app reimplements the convention
> Summary: Tess's convention for an app's own data (a marked group among home's subgroups, union read, smallest tid written) leaves each app to find or create the group correctly and to merge duplicates from nodes that started offline, per piece of data. Ask: a helper in the `osis` crate that does both.
> Tags: core-ask, api

The convention itself is decided (notes/app.md, kit and app). The membership footgun (a group added to home as an item but not as a subgroup) now fails loudly (notes/api.md Writes); what remains:
- **Find or create**: the app creates the group as both an item and a subgroup of home and marks it; every app repeats this.
- **Duplicates**: two nodes starting offline each make a group (plus whatever they create in it). The app then needs a merge rule per datum: favorites (union, removal from every list, moves only within one list), theme and mode (first set wins), per-node open entry (any group, moved to the main one), duplicate built-in things (smallest tid shown). Review found lost-removal bugs here twice. Ask: `app_group(marker) -> Tid` (find or create correctly) and either a merge-on-sight step core runs once both are known, or documented helpers for the common shapes (a set or list spread over groups).
