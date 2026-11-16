# Apps' own data: find or create, and duplicates
> Summary: An app's own data (favorites, arrangements, its built-in things) lives in a thing the app finds or creates among what the user's nodes hold (home is the app's, issues/reference-graph.md). Each app must find or create it correctly and merge the duplicates two nodes make when they start offline, per datum. Ask: a helper in the `osis` crate that does both.
> Priority: low
> Tags: core-ask, api

- **Find or create**: every app repeats it (notes/app.md, State in osis).
- **Duplicates**: two nodes starting offline each make one (plus whatever they create in it). The app then needs a merge rule per datum: favorites (union, removal from every list, moves only within one list), per-node open entry, duplicate built-in things (smallest tid shown). Review found lost-removal bugs here twice.
- Ask: `app_root(marker) -> Tid` (find or create correctly) and either a merge-on-sight step core runs once both are known, or helpers for the common shapes (a set or list spread over duplicates).
