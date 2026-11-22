# blob-wait-memory
> Summary: footguns met while bounding blob-wait walk memory.

- Forging a root list under `small_pages()` (target 400): a root list holds one link, so a reroot adding a link fails ingest with "link list above the page target"; a test needing a several-link root list uses `target: 1000`.
