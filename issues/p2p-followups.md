# P2P follow-ups
> Summary: IPv6 LAN discovery uses only the default network interface.
> Tags: sync, networking

1. **IPv6 on several interfaces** (spec/sync.md §10): ff02::1 announcements go out the default multicast interface only (`lan::multicast`, interface 0). A host on two IPv6 LANs is heard on one. Fix: send per interface with its scope (netwatch lists them).
