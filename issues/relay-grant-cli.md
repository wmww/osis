# Making a node of another account relay a chat: no CLI view of invitations, two grants by hand
> Summary: a node of a third account relays a chat only when granted sync on the chat and on its link's K and when it accepts both (notes/dogfood.md); the CLI has no `invitations` or `accept`, `group add` accepts silently nothing when run before the grant arrived, and finding K means reading `link ls`.
> Priority: normal
> Tags: cli, chat, dogfood

- Accepting = listing under a synced group (`group add home T --subgroup`, through `mark_acted`); before the inbox blob is held it lists T and keeps no sync ID, with no error. A CLI `invitations` (local engine; also through the port, issues/client-port-listings.md) would let the operator check first, and `accept T [--into G]` name the step.
- K: a joiner redeems the link at a node sharing K (spec/permissions.md §7 First contact), so the relay needs K as well as the chat. A chat-level `chat relay CHAT ACCOUNT` (sync on the chat and on every working link's K, and on links made later) would keep the two together; today a new link needs its own grant.
- `card show` and `card import` do not run through a daemon (issues/client-port-listings.md): the host prints its card before starting, a member imports before its daemon starts.
