# keel-forged-d
> Summary: Mishaps met fixing D's ticket for a thing kept unread.

- `Engine::rotate_leaving_out` (testing hook) fired no tickets, unlike every real rotation, so a kept-unread holder never learned the new secret in an osis-sync test; it now fires them to `rotation::unreached` as `rotate_boxing` does.
- `ticket_for` returns the newest-epoch ticket held, a forged one included: a test wanting the genuine one must take it before placing the forgery.
