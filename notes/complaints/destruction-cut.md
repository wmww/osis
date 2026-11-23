# destruction-cut
> Summary: Footguns met fixing destruction-by-removed-direct-admin.

- `tools/heavy cargo test ... -- --ignored paths:: _plain` ORs the filters; heavy refuses it (exit 1) but my `| grep` hid the message: run property lists with `--exact` names, unpiped to a log.
- `tools/mutate.py` refuses an OLD occurring twice; the `FILE:LINE` form fixes it, but the error only shows in the background output.
