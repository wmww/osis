# grant-design-review
> Summary: mishaps while reviewing the grant design.
- `pkill -f <pattern>` from a Bash call matches the call's own shell (exit 144). `kill` a pid taken from `ps`.
- `timeout N bin | tail` loses all output on timeout: log to a file.
- `share_into` and raw edge writes grow slow per thing (230 ms at 100 things, 720 ms at 200 through `Osis`; 10-60 ms per thing at the engine): a 10^4-roster world cannot be built in a test by the public API. Not looked into beyond that; worth a scale check of its own.
