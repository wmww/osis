# app-time-test
> Summary: worker complaints for the app time test fix.

- An app test read "now" and the system zone, so the gate went red for every branch on the night before a DST change. Tests that touch time should pass zones and times explicitly (`span_in`, `nudged_in`).
