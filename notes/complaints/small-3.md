# small-3
> Summary: footguns met on the small-3 branch (removed node's record, listener sets, connection diagnostics).

- The siblings fixture's plain things travel under D's sync ID, so a test needing a thing's own sync ID needs a grant or link first; nothing says so where `file` is defined.
- The dialable `peer://` listener's address was observable nowhere (reach.0 lists global addresses only, so loopback tests see none): added `Internals::listening`.
- A mutation probe of the listen fix hangs 120 s (the common `block_on` timeout) before failing.
