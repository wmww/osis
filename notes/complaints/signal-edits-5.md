# signal-edits-5
- The design note said `replace` + `Purge::Commit` in one write was built, but in a disappearing chat it failed ("a commit has one expiry"): the API always added a `purge.0` delta, which never expires. Step 4's tests had no required expiry beside an edit; fixed here (a request goes under the write's own delta on the thing).
- `cargo build -p osis-app` from the root says "no such package": the GUI workspace is libs/kit/ (notes/build.md says so; easy to forget).
