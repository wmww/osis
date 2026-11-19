# s1-streams
> Summary: Mishaps met on S1 briefs 1-2 (streams by record).

- `store rows read` had no per-caller split: finding who read them took a throwaway backtrace probe in osis-base (line-tables builds show short frame names, so file:line keys). `osis_base::costs::scoped` now splits it by module; a call-site split still needs the probe.
- The idle tests each rebuild their worlds; the ignored `probe_counts` with a backtrace probe on every row read took 3 minutes.
