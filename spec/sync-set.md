# Sync: what a node syncs
> Summary: Area 1: the synced group, the sync set it gives each node, leaving the set, invitations and accepting them, and writing through another node.

**Principle:** a node syncs exactly the sync IDs of the things in its synced group's closure that it may hold; nothing else decides (no list of peers or of sync IDs to keep). The account chooses what is listed; what the node may hold filters it.

## 1. Synced group
- Each node N of an account P has one **synced group** G_N: a plain group whose first admin is P's devices actor D, an item of D's `group.0`, listing D as a subgroup from its making. `synced^.0` on D maps each node's tid to its synced group (spec/data-model.md §9); it is admin-only and travels under home (D's home sync ID), so only P's nodes read it.
- A node learns its own synced group with its grant on D: in the account's creation (the first node: the commit creating D carries the synced group and the `synced^.0` entry, after the role commit, in one transaction) or in the pairing reply (a later node: a synced group holding a copy of the pairing node's synced group's items and subgroups).
- **Home stays under it**: a node MUST NOT write a commit after which some node's synced group closure no longer holds D, or D's closure no longer holds that synced group, while each held the other before: the write is refused locally (`Invalid`). Limit: two concurrent writes each cutting one path leave that node following no change of its synced group until it is paired again.
- Before a node has read its synced group (a fresh pairing), its sync set is home's closure.
- Organizing groups ("on every node", "nodes with room") are plain groups listed under synced groups; they have no sync ID of their own role and no special rule. Which exist, and where an accept writes, is the app's or the node's policy.
- **Dial list** `dial^.0` on P's profile: each node's dialable key to its URLs, written by the account, each node keeping its own entry (writing it for its new key removes the one for its old); P's contacts read it for dialing only (spec/sync-opens.md §1). The account's creation lists the profile as an item of D, so every node of P syncs it. A node learns P's profile as it learns its synced group: at the account's creation, or from pairing (the offer names it), before the profile itself arrives.
- No group names a node: groups name accounts, never their holders' nodes.

## 2. Sync set
- **Closure** of a group G: G, the groups its `group.0` lists as subgroups, transitively, and the items of all of these (spec/data-model.md §8), each as a thing. A cycle adds an element, never a loop. The sync set follows every `group.0` change the node applies.
- The closure is walked only through groups the node reads: a thing the node keeps unread is a **leaf** (its `group.0` is unread, so nothing it lists is in the closure through it).
- **Sync set** of node N: for each thing T in G_N's closure,
  - T's home sync ID when N holds a read secret or a sync secret of T (read, or kept unread, spec/sync.md §3);
  - nothing of T's own when T has no secrets of its own: a plain thing travels under the sync IDs of the groups holding it (spec/sync-judgement.md §1). Whether T has secrets of its own is spec/crypto.md §3's count from the role commits the node holds: a thing whose keyset commit it does not hold counts as plain until one arrives.
- A thing of the closure that has secrets of its own and of which N holds neither a read nor a sync secret is **unsyncable**: nothing of it syncs at N, and the node reports it (`Unsyncable`, a diagnostic).
- A received grant syncs nothing until the account lists its thing in some node's synced group closure (§4). A link's sync ID is in the redeemer's sync set, read, while it redeems the link (from the link text until a held `sync.0` records it, spec/sync-inbox.md §6), whatever it holds of K.
- **Cost**: a `group.0` change that adds a subtree costs work in proportion to that subtree; one that removes costs at most work in proportion to G_N's closure.

## 3. Leaving
- S leaves N's sync set when its thing leaves G_N's closure, or N stops holding any secret of it. One rule ends syncing it: N stops syncing S once what it logged itself under S is elsewhere, at once when it logged nothing there: reading S, each of its own commits with an entry under S is **held elsewhere** (spec/sync-status.md §2); keeping S unread, each entry it logged itself under S (its deposits) is present, by blob ID, at a source. While it waits, S stays a member of its shared sets as before. Synced again before then, S is kept as it was.
- **Unsyncing**: when T left G_N's closure and N still reads it (it holds a read secret of T's own), N, on stopping S, forgets its local copy of T and of each thing whose secrets are T's and that G_N's closure does not hold: their content goes, their role-class aspects (`secrets.0` included) stay, and what arrives again later counts as never received (spec/commits.md §4). This holds for any thing, whoever holds it elsewhere: unsyncing a thing on every node holding it loses it, as deleting a local file does.
- A node removed by another can open S nowhere: reading S, it holds no secret of the thing (spec/permissions.md §3 Lost access) and stops at once; keeping S unread, it drops its copy once its head moves past its keys (spec/sync-judgement.md §6 Stops). A self-remover keeps the secrets until its self-removal is held elsewhere (spec/permissions.md §3).
- On stopping, N closes S on every connection, drops S from every record in that step (spec/sync-opens.md §3), and shreds S's entries in its store (keys and wraps erased).
- Lowering from read to sync is no leaving: S becomes kept unread with its store (spec/sync.md §3).
- A destroyed thing's own sync IDs stay in the sync set until emptied (spec/sync-judgement.md §5), whether or not the thing is still listed.
- A thing whose role the account lost stays listed in the synced group: the group holds what the account chose, the sync set filters it.

## 4. Invitations and accepting
- A received grant is data the account holds; accepting is data it writes; core only lists. **Invitations**: the things with a sync ID the account holds a role on (by grant copies and rosters) that are in no node's synced group closure, each with its role, its granting account and whether its inbox blob was taken (spec/sync-inbox.md §2).
- **Accepting** writes the thing as a subgroup (never an item) of a synced group or of a group under one. The accept is a commit on that group's `group.0`, under home alone.
- **Declining** is the app's: `leave` (a self-removal), or filing the thing in a group outside every synced group. Neither is a diagnostic or a status.
- Importing a contact card accepts the profile it names.
- A holder whose highest role on a thing is sync keeps no subgroups of it: a new subgroup is kept only once granted too.

## 5. Group source
- A node MAY read and write a group through another node it is a client of (the group's source, spec/sync-transport.md §6).
- A thing in a group sourced at another node goes there, whatever else holds it; the copy this node holds never answers.
- A write on it is refused while a group carrying it (spec/sync-judgement.md §1) syncs here or is sourced at a second other node (one other than the source the write goes to).
