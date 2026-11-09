# kestrel-net-shared-design
- The issues name "Current" and "Holders for keys" as spec/crypto.md §4 terms; the code's matching judgment (per actor, transitive, departed) has no function yet, so the design's J is not checked against code.
- The filter's false-positive bound in the old text ("whatever the sender sends") held only with the receiver fixing `f`; the old Offer format also named the sync ID on a false positive. Worth a line: a design claim about an adversary needs checking against its wire format.
