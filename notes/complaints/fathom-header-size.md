# fathom-header-size
> Summary: worker complaints from the header-size-sensitive tests job.

- The issue's "IDs alone don't break it" was a misleading lead for the scale test: a header-size change moves every ID too, and the cause was hash-bucket stamp sharing (ID-dependent). Changing only `draw_blind` happens to land the bucket collision elsewhere.
- Diffing two `OSIS_SYNC_TRACE` runs is hard because every hash differs; grepping for up/close/Prove lines was what worked.
