# d2-held complaints
- `tools/mutate.py` refuses two mutations sharing an OLD site in one batch ("overlap"), so a control and a joined control over the same site take two builds; and an OLD like `self.req(rule, s, &st.units, &held)` occurring twice needs the whole enclosing `if` as OLD.
- `tools/policy.py` checks every backticked name in notes against the code, so cutting a model means editing every finding that cites a removed function or test, the registry's history included (24 hits here).
- `claudewait` needs the task ID of the call that started the background run; an ID typed from memory of another call fails with "unknown task ID" rather than waiting.
