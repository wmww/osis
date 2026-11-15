# fathom-rebuild-review-10
- `Engine::check_index` reports only the first differing table (`first_diff`), so placing several left-out indexes into the check took one full engine run per diverging table to see the next.
- Engine test worlds hold nothing in a node's sync set unless filed under D by hand (`granted` groups are read nowhere), so `certificate_lists` stays empty and a leak test passes vacuously until the thing is filed.
