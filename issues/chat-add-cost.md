# A chat's add costs each node O(members + messages)
> Summary: After the per-pass fixes a post is about flat in members, an add is not: each node pays about 0.8 ms per member and 120 us per message per add (a full pass of the label), a joiner 16 ms per earlier member and 1.1 ms per message, and an admin a pass per label it syncs. Repro and numbers: `scale::chat_members`, notes/testing.md.
> Tags: engine, node-sync, performance

The per-pass secrets decode this began as is gone (`Core::secrets_read`, `held_for`, `head_keys`, `Work::beats_*`, `mark_dirty_of`; 100 members joining from over 20 min to 357 s on the sim, a receive at 20 members from 8.5 to 1.5 ms).

Left, largest first:

1. **An add makes every node pass the whole label: O(messages).** `prepare` goes full when the label's own actor's roster moved ("every entry's author may stand anew"): 20 members, an add per other node 21 ms with no messages, 210 ms at 2000, 1.2 s at 10^4, so about 2 min at 10^6. An add only raises one holder: only that holder's entries change standing. Narrowing it needs the verdicts' reads pinned down; `work_sets_*` is the oracle.
2. **An add at each node: O(members).** 78 ms at 100 members: applying it about 30 ms (the state's pages, `observe_state` decoding `secrets.0` whole), timelines 15 ms, `departures` walking each holder 16 ms with the decode, heartbeats read again after the full pass 4 ms. Over a whole chat that is quadratic per online node: about 400 s at 1000 members, if it stays linear.
3. **A joiner: O(members + messages).** 16 ms per earlier member (16 KB down per member: its add commit and card), 1.1 ms per message. Per-commit work, no longer per-commit-pair (`apply/waits.rs`).
4. **An admin: O(labels it syncs) per role commit.** Every role commit marks every label dirty; an admin that met each member has a label per contact, two passes and a `departures` walk each: `share` 187 ms at 100 members. A commit that only raises could mark only labels near it, but a lowering may be a revoke other labels must copy (`revoke_certificates`). Joining by link avoids the contacts. Also about 20 us per label on every step of the sync engine (`labels`, `retire_replaced`): an admin's post 4.4 ms at 100 against a plain member's 2.4.
5. **Store: 52 KB per member at every node**, 176 KB at the host (its own labels, cards): 52 MB per device at 1000 members, 520 MB at the 10^4 target. Each add keeps three boxes and a history box for good; a chat's roster never compacts (notes/chat-designs/e.md).

Not measured: kicks at these sizes (issues/long-aspect-cost.md has them by messages), 1000 members all online (M nodes in one process do M^2 work per add; see the table's note).
