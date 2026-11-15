# Signing-chain lines go as `keys.0` copies, the spec says header-only
> Summary: spec/permissions.md §4 (Chain certificates) and §5.5 (Chains travel) log an account's rotations "as header-only copies, every line"; `Engine::account_chain` adds each rotation's `keys.0` part (a certificate copy carrying that epoch's public keys and D's deposit seed).
> Priority: normal
> Tags: engine, sync

- Only the current `keys.0` commits need their part (`current_keys`). Older lines verify the chain by their rotation header alone, and each copy carries an old deposit seed the readers of S need for nothing.
- Fix: older lines into `Certs::headers` (judged as header-only certificate copies under spec/sync-judgement.md §2), or change the spec if a part is needed. Check what judges `Certs::headers` today: it is documented for destroying requests.
