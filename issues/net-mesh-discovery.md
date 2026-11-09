# Reaching nodes across hops and carriers
> Summary: Target the rework must not work against, not built now (Tess): A and B on local Wi-Fi with no internet, C paired to B over Bluetooth, and A and C in one chat as if all were online, even one B is not in. Discovery today covers one broadcast domain, known addresses and any reachable node. Privacy, quotas, defaults and configuration stay open, possibly past 1.0.
> Priority: low
> Tags: transport, spec

## Target
A node reaches another through a node between them, over any carrier, whether or not the node between holds or can read the data. spec/requirements.md's "dynamic mesh with no internet at all" keeps its full wording.

## What stays open
How far a node's presence travels, who may pass traffic through whom, quotas, what is on by default, how it is configured. These may change after 1.0, so no job fixes them.

## What a job must not do
issues/net-rework.md, Rules for every job (Reachable through anything).

## When built
A later job beside issues/net-connect.md's "Nodes that never met". Rejected: each node re-announcing what it hears one hop on (n² datagrams per round on a segment of n nodes, reaches two hops and not three). Passing presence on needs a rule that reaches any hop count, with de-duplication; its cost and address exposure (issues/privacy.md) are that job's design.
