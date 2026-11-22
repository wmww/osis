# Complaints: must-hold-reader
> Summary: the shrunk script names nodes by index while the failure names things by tid, with no map between them; `tools/heavy` holds queued for minutes behind others.

- The quiet check's dump names S's things and the commit's things by tid; the script names things by index. Telling `t0` from the account root (both stable across the original and shrunk run) took a scratch probe printing `w.history.things` beside `sync_ids_of`. Printing the history's thing index beside each tid in `lost_body` would have saved the probe.
- Three `tools/heavy` holds (a 50-world rate, a seed replay, the suites) each waited 5-8 minutes for the lock behind other agents' runs; a 50-world rate of an 8-step script is about 300 CPU-s, just over the short lane's cap.
- A retention change's storage cost shows only in `growth::` and engine `closure::` tests, not in the differential: run those before measuring a differential rate as a fix.
