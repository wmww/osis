# watchdog
- A reviewer's gate log is overwritten by its rerun (`$D/gate.log` again), so a first gate refused at the instant checks leaves no record but the transcript: counting those refusals took a transcript scan.
- `tools/limits.py summary` prints UTC times, `tools/heavy --report` and `agent-times.py` local ones: line up a session's gates by converting first.
- limits.log has no gate exit code and the heavy log only the hold's: a gate's own exit (0/1/3) is only in its log's last line.
