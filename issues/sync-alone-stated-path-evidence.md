# A writer of a sync-alone holder shows its readers the holder's grant by a stated path
> Summary: a writer of H, where H holds sync alone on X, signs a body under H's sync ID stating a path through (H, X); evidence takes every write on that edge whatever its validity, so every node reading H and holding X's role commits logs X's grant to H (header, signer, path) and X's record as certificate copies, which spec/sync-ids.md §2 What a sync holder learns keeps from H's readers.
> Priority: low
> Tags: security, engine, perm

**Decided (Tess):** accepted, a violation of the strict model not acted on before shipping (only H's own writers can do it); fix it if a way comes up with no added complexity or other tradeoff.

- Stated in spec/sync-hostile.md §2. Pinned by `tests_delivery::a_writer_of_a_sync_holder_stating_a_path_through_its_edge_shows_its_grant_spec_sync_hostile_2`: T's admin grants G write on D (T's), then signs an invalid body on D stating [T, G]; peer 0 (G's admin, a reader of T) carries G's grant to T and G's record under T's sync ID. The test asserts the leak: a fix flips it.
- Who writes the input: any writer of H (no role on X needed; the path's last hop (X, D) needs only a grant D's admin may write). Who learns: H's readers, the writer among them: who granted H sync on X and along what path.
- Such a body is never valid (sync on X gives no authority through it), so its readers need the edge's writes only to judge it invalid. A fix likely makes a hop through an edge of a holder of sync alone bring sync copies only, the body pending or invalid at H's readers; that puts a verdict into evidence of a commit (validity-free by design, spec/permissions.md §4), so it needs the same care as the read graph's.
