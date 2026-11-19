# s3-overlap
- held-model `gen::shuffle` reorders commits, records and frontiers but not `Held::dots`; `Dots::commit` takes the first range holding a dot, so an order test over overlapping ranges must shuffle `dots` itself (`props_overlap::reorder`).
- held-model judges validity, settings, fires and purge in one long `judge`: a rule layered on validity has to be spliced in by hand between them; no named stage order to read.
