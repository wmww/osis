# churn-snap
> Summary: workflow mishaps met on the churn-snap branch.

- Debug env vars named `OSIS_*` make every harness panic (testenv's known-variable check), and sim-sweep's silenced panic hook hides why: exit 101 with no message. Use a non-`OSIS_` name for throwaway debug switches.
- Sim traces don't say which node an entry or tid belongs to, or why a host refused a pulled entry (`unread_events` drops non-OK codes other than cap and tombstone silently); finding the refused rotation took ad hoc prints in five files.
