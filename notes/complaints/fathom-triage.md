# fathom-triage
> Summary: footguns met reviewing opened_under_wrap.

- `OPENED_UNDER` rows were keyed by epoch alone, while the epoch's thing changes meaning (a copy's opening is of the sync ID's thing). Any new check reading those rows under a different thing silently trusted foreign epochs; the thing is in the row now.
- LocalPeer's plain delivery carries every commit as read in no section, so passing-on tests must withhold the commit under test and feed it through `seal_body`/`open_entry` by hand.
