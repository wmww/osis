# A bare-anchor text slot hides a register write
> Summary: At a `Slots` position, a register write of a non-string value over older text reads absent while the text slot keeps that text's bare anchors (the slot ties the register on stamp and wins on encoding id), but reads the value where no such record is held; found by `tests_join::settled_reset_keeps_above_any_encoding_spec_7`.
> Priority: low
> Tags: crdt

spec/crdt.md §7: the register write at `s` embeds as reset `s` into the text slot; the text slot's greatest stamp is then `s`, equal to the register's, and the tie goes to text (encoding 9). With only bare anchors left (§4.2: sequence records survive the reset) the slot is not "adding nothing to the embedding", so it is kept, chosen, and reads absent. Without the old text's records the slot goes and the register's value reads. Same bodies read alike, so nodes converge; the read just depends on whether old text records exist. Candidate rule: bare anchors do not count for keeping a slot or choosing it (they carry no stamp), or the register wins ties.
