# CLI `serve`: the hosting config is write-only
> Summary: `osis serve --label ID` takes a label ID no command shows, and the CLI cannot show `host.0^`, stop hosting, or set `replicate`, `policy` and `caps`; small CLI additions.
> Tags: cli

- Found in the sweep step 8 review.
- `--label` wants 32 hex digits, but no command prints a group's label IDs (`status` shows groups only). Show them in `status --json` (or `group show`), or let `--label` take a group selector and resolve its current label.
- No way to read the config (`db.hosting()`): e.g. `osis hosting` printing `host.0^` and the host address.
- No way to stop (`set_hosting(None)`) or to clear `--label`/`--listen`: e.g. `osis hosting off`.
- `replicate`, `policy` knobs and per-label `caps` are API-only.
