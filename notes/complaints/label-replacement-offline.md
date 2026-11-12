# label-replacement-offline complaints
> Summary: what slowed the label_replacement_offline fix.

- The sim's failure message names a count, not the entry: finding the stuck commit, its parts and why the node kept it took temporary eprintlns in both the scenario check and node sync's `judge`. A failure detail listing each leftover entry's commit, aspects and the admin's fate for it would have cut that to one run.
- The obvious minimal test (overwrite and compact before replacing) passed on the broken code: the node rewrites a dropped body's entry before replacement, so the bug needs the drop to happen after the replacement and before the delete reaches the host. Checking the test against the old code by hand caught it.
