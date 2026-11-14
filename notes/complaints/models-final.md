# Complaints: models-final
> Summary: Workflow snags met while bringing the area-4 TLA models in line with the spec.

- `run.sh` hides which property a negative control failed on; checking "fails for its stated reason" needs TLC_KEEP_LOGS and a grep per log. Printing the violated property beside `fail` would save that step.
