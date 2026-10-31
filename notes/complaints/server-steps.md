# server-steps
- Dropping a field from a wire message also needs the arity table in `msg.rs` `decode_body`; missing it gave no decode-test failure I saw first, only osis-crate tests timing out ("future did not resolve", status stuck Syncing). A round-trip test per example message would catch it at the proto level (the `examples` vectors do, but only once regenerated).
