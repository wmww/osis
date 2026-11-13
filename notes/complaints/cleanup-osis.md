# cleanup-osis
> Summary: Complaints from the osis-crate cleanup.

- `tools/dead_pub.py` found nothing in core/osis: the volume there is duplication (one value decoded several ways, near-identical watches, copies of a helper), which a name scan cannot see. A cleanup brief pointing at dead_pub first sends the agent to an empty list; a repeated-window scan (4 stripped lines seen twice) found more.
- The brief cites "the cleanup-retention complaint" in notes/complaints; no such file is there (deleted by a watchdog), so the rule it carries (helpers costing as many lines as they save) lives only in briefs.
- Removing a parsing helper made `osis-schema::TID` live, failing dead_pub on a stale allow-list line: touching core_types keys from osis can flip another crate's allow-list.
