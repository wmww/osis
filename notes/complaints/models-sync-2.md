# Complaints: models-sync-2
> Summary: Workflow snags met updating the net TLA models to the sync-rebuild spec.

- Editing `core/test/tla/run.sh` while a background `run.sh` runs breaks the running copy (bash reads the script as it goes: "il: command not found" at its end). Register cfgs before starting a run, or copy the script.
- The `S_*`/`SN_*` cfgs have no first-line comment although the net README says every cfg's first line says what it checks; a cfg generator that drops line 1 silently drops `SPECIFICATION` there.
- `DeletionsArrive` does not hold once a copy, a delete and an expiry meet (a deletion the copy still logs sits below a cursor read past its expiry at the original): no positive cfg combined them before, so the first such cfg fails on a known limit, not on the change under test.
- The one-worker module runs no longer fit "under 3 min" for netstream (`SN_joinans` alone is 134 s).
