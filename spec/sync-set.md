# Sync: what a node syncs
> Summary: Area 1: the synced group, the sync set it gives each node, leaving the set, invitations and accepting them, and writing through another node.

**Principle:** a node syncs exactly the sync IDs of the things in its synced group's closure that it may hold; nothing else decides (no list of peers or of sync IDs to keep). The account chooses what is listed; what the node may hold filters it.

## 1. Synced group
- Each node N of an account P has one **synced group** G_N: a plain group whose first admin is P's devices actor D, an item of D's `group.0`, listing D as a subgroup from its making. `synced^.0` on D maps each node's tid to its synced group (spec/data-model.md §9); it is admin-only and travels under home (D's home sync ID), so only P's nodes read it.
- A node learns its own synced group with its grant on D: in the account's creation (the first node: the commit creating D carries the synced group and the `synced^.0` entry, after the role commit, in one transaction) or in the pairing reply (a later node: a synced group holding a copy of the pairing node's synced group's items and subgroups).
- **Home stays under it**: a node MUST NOT write a commit after which some node's synced group closure no longer holds D, or D's closure no longer holds that synced group, while each held the other before: the write is refused locally (`Invalid`). Limit: two concurrent writes each cutting one path leave that node following no change of its synced group until it is paired again.
- Before a node has read its synced group (a fresh pairing), its sync set is home's closure.
- Organizing groups ("on every node", "nodes with room") are plain groups listed under synced groups; they have no sync ID of their own role and no special rule. Which exist, and where an accept writes, is the app's or the node's policy.
- **Dial list** `dial.0` on P's profile: each node's dialable key to its URLs, written by the account, each node keeping its own entry; P's contacts read it for dialing only (spec/sync-opens.md §1). A node's own `reach.0` (spec/sync-transport.md §1) is for P's nodes.
- No group names a node: groups name accounts, never their holders' nodes.

## 2. Sync set
- **Closure** of a group G: G, the groups its `group.0` lists as subgroups, transitively, and the items of all of these (spec/data-model.md §8), each as a thing. A cycle adds an element, never a loop. The sync set follows every `group.0` change the node applies.
- The closure is walked only through groups the node reads: a thing the node keeps unread is a **leaf** (its `group.0` is unread, so nothing it lists is in the closure through it).
- **Sync set** of node N: for each thing T in G_N's closure,
  - T's home sync ID when N holds a read secret or a sync secret of T (read, or kept unread, spec/sync.md §3);
  - nothing of T's own when T has no secrets of its own: a plain thing travels under the sync IDs of the groups holding it (spec/sync-judgement.md §1). Whether T has secrets of its own is spec/crypto.md §3's count from the role commits the node holds: a thing whose keyset commit it does not hold counts as plain until one arrives.
- A thing of the closure that has secrets of its own and of which N holds neither a read nor a sync secret is **unsyncable**: nothing of it syncs at N, and the node reports it (`Unsyncable`, a diagnostic).
- A received grant syncs nothing until the account lists its thing in some node's synced group closure (§4). A link's sync ID is followed as its redeemer redeems it (spec/sync-inbox.md §6).
- **Cost**: a `group.0` change that adds a subtree costs work in proportion to that subtree; one that removes costs at most work in proportion to G_N's closure. Both counted at n and 10n in tests.

## 3. Leaving
- S leaves N's sync set when its thing leaves G_N's closure, or N stops holding any secret of it. One rule ends syncing it: N stops syncing S once what it logged itself under S is elsewhere, at once when it logged nothing there: reading S, each of its own commits with an entry under S is **held elsewhere** (spec/sync-status.md §2); keeping S unread, each entry it logged itself under S (its deposits) is present, by blob ID, at a source. While it waits, S stays a member of its shared sets as before.
- A node removed by another holds no secret of the thing (spec/permissions.md §3 Lost access), can open S nowhere and stops at once. A self-remover keeps the secrets until its self-removal is held elsewhere (spec/permissions.md §3), so the one rule covers it.
- On stopping, N closes S on every connection, drops S from every record in that step (spec/sync-opens.md §3), and shreds S's entries in its store (keys and wraps erased); what S carried stays local data as the engine holds it.
- Lowering from read to sync is no leaving: S becomes kept unread with its store (spec/sync.md §3).
- A destroyed thing's own sync IDs stay in the sync set until emptied (spec/sync-judgement.md §5), whether or not the thing is still listed.
- A thing whose role the account lost stays listed in the synced group: the group holds what the account chose, the sync set filters it.
- Removing a thing from every node's synced group drops it from every node of the account once their own commits are held elsewhere, even when no other account holds it (it may lose the last copy). (Open question for Tess.)

## 4. Invitations and accepting
- A received grant is data the account holds; accepting is data it writes; core only lists. **Invitations**: the things with a sync ID the account holds a role on (by grant copies and rosters) that are in no node's synced group closure, each with its role, its granting account and whether its inbox blob was taken (spec/sync-inbox.md §2).
- **Accepting** writes the thing as a subgroup (never an item: an item's subgroups would be outside the closure) of a synced group or of a group under one. The accept is a commit on that group's `group.0`, under home alone, so no other holder learns which accounts sync the thing.
- **Declining** is the app's: `leave` (a self-removal), or filing the thing in a group outside every synced group. Neither is a diagnostic or a status.
- Importing a contact card accepts the profile it names.
- A holder whose highest role on a thing is sync keeps no subgroups of it: a new subgroup is kept only once granted too. (Open question for Tess.)

## 5. Group source
- A node MAY read and write a group through another node it is a client of (the group's source, spec/sync-transport.md §6).
- A thing in a group sourced at another node goes there, whatever else holds it; the copy this node holds never answers.
- A write on it is refused while a group carrying it (spec/sync-judgement.md §1) syncs here or is sourced at a second other node (one other than the source the write goes to).
