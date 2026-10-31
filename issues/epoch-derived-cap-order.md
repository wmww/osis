# Derived epochs past the cap order by nonce
> Summary: owner epochs above 2^62 (a writer of the owner jumped them) all derive at n 2^62 − 1 (spec/crypto.md §3), so later owner rotations give derived epochs newer than the old only by nonce; `newer_than_head` then skips re-registering a plain group's labels about half the time (a removed device keeps that label's old sync and write keys at servers).
> Tags: security, keys, sync

Needs a malicious writer of the owner first; nothing is wrongly encrypted. Fix direction: re-registration also counts a head epoch superseded by an established epoch as stepped past (spec/sync.md §5), independent of n.
