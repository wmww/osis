# fathom-review-inbox
- `cargo test ... a:: b::` with several filters piped to grep printed nothing (cargo refused the extra args; grep hid it). One filter per run, or check the raw output.
- The contacts/history worlds keep every contact a link dial hint, which masks an inbox blob's own dial hint: a test of the latter needs the link's role gone first (links.rs).
