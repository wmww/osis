# Engine module cleanup left over
> Summary: Simplifications of osis-engine `engine/` not done: legacy store layouts still read (owner decision), and two key-index pruning routines that might be one.
> Tags: engine

No failing test; behaviour-preserving refactors unless noted.

- **Legacy layouts**: `pages::legacy` reads unit tags 1-6, `index::parse_head` record heads of version 2, `old_judgments` the `node/parts` rows, `decode_epochs` the 7- and 8-field epoch items, `parse_top` tops without `newest`. Pre-release, so these could go together, with stores from those builds refused (or rebuilt where the data is rebuildable). Needs an owner decision: it drops read support for old stores.
- **Two key-index pruning routines**: `pages::strip_touched` records the touched elements' keys before stripping and removes the rows no longer indexed; `pages::unindex` does the same for dropped bodies from the bodies' own keys. One routine over the bodies would save about ten lines, but touched dots and the bodies' dots differ (removals, `Derived` set elements read as a superset) and a merged one may remove more rows (stored bytes change); only with a randomized differential of the key rows first. Judged not worth it in the engine-cleanup branch.
