# test-speed-2
- A test run under a harness needs its binary copied aside before any edit (`tools/pertest.py` does it; a by-hand `icount` before/after does not): the next build overwrites `target/debug/deps/<bin>` under the same name.
- `tools/code_refs` reads `` `rotation_holds` `` as `rotation_holds_spec_crypto_4` with its spec tail cut, so renaming a test breaks note references that never named it whole; run policy.py right after a rename.
- A delivery-equality probe needs the same probe in the old and new builds: save the change as a patch, build probe+change, reverse the patch, build probe alone.
