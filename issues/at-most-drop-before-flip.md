# Keep-at-most drops before a validity flip depend on order
> Summary: A body under keep at most dropped when its write was killed stays dropped if the killer later turns invalid, while a node that judged the killer invalid first never drops it: nodes holding the same commits then differ in what they hold (spec/requirements.md Decentralization).
> Tags: retention, node

Repro: the order harness with keep-at-most-0 writes by members (order.rs restricts ops 18-20 to the owner because of this); shrunk: `vec![Write { by: 2, t: 4, op: 18, k: 2, v: 4 }, Write { by: 1, t: 6, op: 18, k: 1, v: 4 }, Demote { by: 0, t: 4, member: 2, at: 3, to_read: false }]` (seed 1053), and seed 1024 `vec![Write { by: 0, t: 7, op: 18, k: 0, v: 9 }, Edge { by: 0, t: 0, member: 2, role: Some(Read) }, Write { by: 2, t: 4, op: 18, k: 2, v: 4 }]`.

The drop is irreversible (the bytes are erased); a revived write survives in the state only if it was live there. Directions: delay drops under keep at most while a killer's validity can still change (it always can, offline admins), or accept and state it in spec/commits.md §5 next to "bounds may differ between nodes until they hold the same commits".
