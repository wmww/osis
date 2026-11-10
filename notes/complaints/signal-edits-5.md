# signal-edits-5
- The design note said `replace` + `Purge::Commit` in one write was built, but in a disappearing chat it failed ("a commit has one expiry"): the API always added a `purge.0` delta, which never expires. Step 4's tests had no required expiry beside an edit; fixed here (in an expiring commit the engine leaves `purge.0` out; the request rides the write's own delta).
- `cargo build -p osis-app` from the root says "no such package": the GUI workspace is libs/kit/ (notes/build.md says so; easy to forget).
- Review GUI check: a chat made by the CLI opens in the app only by pasting a link, and a link needs a saved peer; a dead peer (`osis peers add 'quic://127.0.0.1:9#<32 bytes base64url>'`) then `link make` (stdout has the link despite the timeout error) works.
