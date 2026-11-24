# Forward-secure deletion rests on an in-place file overwrite; the hardware root tier is unimplemented
> Summary: spec/requirements.md Deletion requires, where the platform offers erasable key storage, that a node that deleted honestly and is compromised later yields nothing. The local store erases unit keys through a key tree whose root is the one thing that must really be erased; the only root storage built is `FileRoot` (two slots overwritten in place with fsync), which SSD remapping, copy-on-write filesystems and cloud disks keep recoverable. Build the hardware tiers.
> Priority: normal
> Tags: security, store

Today deletion is unrecoverable through the filesystem API and against an attacker reading only current file contents, not against block-level recovery. Nothing reports which root storage a node uses (a diagnostic of a best-effort root could come with the tiers).

To build behind the existing `RootStorage` trait, each a platform dependency behind a feature: TPM 2.0 NV index (Linux, Windows), Secure Enclave keychain item (Apple), Android Keystore / StrongBox-wrapped root. Browsers are out of scope (Tess: forward secrecy only where the platform has erasable key storage).
