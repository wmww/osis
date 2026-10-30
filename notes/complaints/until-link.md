# until-link
- The issue assumed every sharer device held the link's seed thing; it was synced nowhere (no group), so only the making device could finalize. Now placed in the home group.
- LocalPeer tests deliver commits unencrypted: any peer "reads" any thing, so confidentiality assertions there are meaningless (only the World tests show who holds what).
- `complete_pass` counts passes from before a reconnect (in-memory, never reset on Down): a device back online judged a pass from before it went offline as complete. Link finalization adds its own "pass ended after `until`" check; re-seal decisions still use the plain one.
- Reviewer: the 30-seed per-branch sweep caught link_race failing once; 200 seeds showed 15%. The gate's 5-seed sweep would likely have missed it.
