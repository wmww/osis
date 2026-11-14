# A reader logs some must-hold bodies only at its next start
> Summary: Under a contact's profile sync ID (read through a redeemed link), a reader's own store holds 2 entries during the session where its first restart logs 13 (certificate copies and role commits must-hold there): read's judgement of those (S, commit) pairs is not woken by what made them must-hold during the session; a start judges every held commit once and finds them.
> Priority: normal
> Tags: sync, read

- Reproduce: osis-sync, `world(0, 3)`, `[New(0), Grant(0, 0, 1, Syncs), Grant(0, 0, 2, Reads), Run]`, then compare each node's entries per held sync ID before and after a power cycle (node 0: the profiles of nodes 1 and 2, 2 entries before, 13 after).
- Effect: until a restart, peers that pull through this node's store lack those certificates; the first restart after such a session commits O(things) (node 2 at 30 things: 73 engine, 177 store commits) where a later one commits nothing.
- Suspects: `Read::bodies` (per commit, `Engine::sync_bodies`, certificate bodies through `certified`) not due when the certificates a sync ID carries move (`Engine::follow` refreshes them; the driver calls it before read), or the profile's sync ID joining the store's syncs after its commits were judged with no body there.
