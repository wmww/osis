# An expired undelete reads differently by whether the creation's char is held
> Summary: an undelete's char is its own value (spec/crdt.md §4.7), so past an expiring undelete's `T` the element's char is the creation's copy alone; a node holding the inserting body shows the char, one bootstrapped from a snapshot taken after the delete (deleted chars never on the wire) does not. Reads differ with no copy to fetch.
> Priority: normal
> Tags: crdt

X types "a" (lasting), Z deletes it, Y undeletes it with an expiry. Before Y's `T` every node shows "a". Past it the undelete's flag `false` stays as the winner and its char goes; spec/crdt.md §5.7 Live then shows the element iff a char is held, and the char is "the creation's copy, else the undelete's". A node that kept X's body has the creation's char and shows "a"; one that started from a snapshot of the deleted state (§3.2: a deleted element's content is never carried) shows "". §5.7 even lets an implementation drop the creation's copy once deleted, so the read is implementation-dependent too. The node lacking the char counts nothing missing (the snapshot covered X's body: its creation died at Z's delete, §4.8), so nothing converges them.

Reproducer: osis-crdt `tests_review::repro_undelete_char_expiry_reads_alike_spec_5_7`.

Candidate rule (follows the value principle and the register rule "a value-less winner reads absent and still beats older writes"): the undelete's value is the element shown again; a text element shows iff it has a char and its winning flag is none or a valued undelete. A value-less undelete (expired, purged, a snapshot's copy of an expiring one before `T`) hides the element as a delete does. Both nodes above then show "". Needs crdt-model first, then osis-crdt, spec §4.7/§5.7, and a check of what the order harness and held-model say about text undeletes under expiry.
