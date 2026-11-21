# cleanup-lower
- `tools/deprecated_probe.py` edits sources in place while it runs (`#[deprecated]` on every item): a read of a file during a probe shows the markers, and an edit then would be clobbered or committed. Run probes before reading, never beside edits.
- Running the probe in a shell loop piped to `head` cut the output and left the probe running past the 120 s foreground limit (it moved to the background mid-loop); write each probe to a file instead.
- The probes stayed thin again (the "unused outside" list is narrowing candidates, not dead code); every real cut came from reading modules.
