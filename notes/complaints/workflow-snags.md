# workflow-snags
> Summary: Mishaps met fixing tools/heavy's short lane, doc_refs' `;` hint, policy's verdict, mutate.py's FILE:N and claim's bisect reset.

- heavy_test's lane runs print a run's code only through `print(rc)` in a subprocess: a KeyError inside `hold` (a test run's dict lacked `bin`) showed only as a missing exit code until the helper was run by hand.
