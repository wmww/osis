# A purge with no reset can show an older value at a new node
> Summary: seen in the gap-cover review: a purge with no reset of the live value left a register reading `None` at the admin and the older `"x"` at a new node. The spec only says the writer SHOULD reset. Not investigated; check if it shows content a user believes gone, and if it is what Tess accepted in question 2B (notes/order-study.md).
> Tags: engine, retention, tests

Scene: `tombstone::a_lasting_request_applies_when_its_killer_left_spec_commits_4` setting, a purge request with no reset. It happens whether or not the commits pend.
