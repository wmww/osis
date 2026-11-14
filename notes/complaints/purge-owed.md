# purge-owed
- A purge test whose purged write is the aspect's first leaves no state to snapshot (`write_snapshot` returns `None`): a re-snapshot test needs an older value under the purged write, or it passes or fails for the wrong reason.
- `LocalPeer::package` of a commit its node already purged carries no body: deliver writes before purging them, or the receiver holds the part missing and the test reads the older value.
