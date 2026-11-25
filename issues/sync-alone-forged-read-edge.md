# An invalid read-giving edge write turns a sync-alone holder's pieces to headers
> Summary: `Core::sync_alone_on` and the evidence read graph count a held edge write on (H, X) giving read whatever its validity, so a party that gets one forged write held at a node reading X and syncing H (or delivering to H) makes that node carry X's real writes naming H (grant, lowering, removal) to H's readers as certificate copies: headers, signers, paths (spec/sync-ids.md §2 What a sync holder learns).
> Priority: normal
> Tags: security, engine, permissions

- Who writes the input: anyone who can log under H's sync ID (H's writers: a certificate copy of a forged role commit on X naming H read, signed by any key along a claimed path, held pending or invalid), or fire an offer on H's inbox where it is enabled. The node that leaks is one holding X's role commits and logging H's key part (an admin or reader of X that also syncs H) or owing H a fire.
- Three routes from one forged write W, each leaking the real writes on (H, X):
  - `sync_alone_on` false: `edge_pieces_into`, `deliver_copy`, `sealed_fire`, offers cut H's pieces as certificate copies;
  - W gives read, so `evidence` puts (H, X) in the read graph: every write on it travels (Role changes travel) into the required set of each sync ID H is open in;
  - W itself travels, and its evidence (Evidence of a commit: every edge write on each edge its own edge writes set) is the real writes on (H, X), headers and all.
- Validity cannot simply decide it: evidence is validity-free by design (validity is judged by it), and the third route needs no predicate at all. A fix has to say what a write on an edge only ever validly giving sync carries to H's readers, likely by the edge's evidence not reaching readers of a holder of sync alone; held-model `box_cut` has no forged edge write to judge it by.
- Pre-existing: on main before the sync-alone removal work, W travelled the same way.
