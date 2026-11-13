# A destroyed group's own label stays
> Summary: When a thing with a label of its own (a group with secrets and `label.0`) is destroyed and keeps nothing, nobody deletes the blobs under its label: they stay at hosts, and node-sync keeps their entries (`y/e`), the headers of its commits forgotten whole (`y/G`, kept while an entry of them is known under any label) and its `s/` row, for good. Its `g/` (`records::OWN_KEYS`) rows stay too.
> Priority: normal
> Tags: node-sync, engine

- Seen in `destruction::a_destroyed_actors_secrets_go_with_the_last_entry_of_its_commits_*`: after the release and every delete under g's label, 22 blobs stay under t's own label at the host and at b.
- The label leaves the synced set with the thing's `label.0` state (`labeled_groups`), so no pass of it deletes anything. A holder of the label's delete key could delete the whole label (label-wide delete) when the group keeps nothing; that needs the group's secrets, now dropped once nothing under a synced label needs them (`retention/destroy.rs::hold_secrets`): a fix must delete before that drop, or count the label as synced until its deletes are done.
- Items of the group under that label live on elsewhere or are stranded (notes/expiry-creation-design.md: a destroyed group strands its items).
