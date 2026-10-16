# LAN discovery leaks a stable identifier
> Summary: mDNS-style LAN discovery (on by default) announces a node's dialable key on every network it joins, letting anyone track the device across networks.
> Tags: networking, security

Anonymity against network analysis is out of scope, but this leak is gratuitous. Options: a dialable key per network, or announcing only on networks the user marks trusted. Context: notes/networking.md.
