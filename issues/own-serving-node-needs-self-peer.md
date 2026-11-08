# A node serving under `own` learns its groups only from a saved peer
> Summary: an `admit own` serving node admits a group only once its own node has synced the group's record, and with no saved peer it reaches that data only by a direct connection to another node of the account, which exists only if one side knew the other's `reach.0` at pairing: otherwise every new label stays `Refused` for good. The setup works around it by saving the node's own serving address as its peer (notes/cli.md Serving).
> Priority: low
> Tags: node-sync

Seen in `osis-chat` `thin::own_serving_node_takes_a_chat_spec_data_model_9` before the test added `dev.add_peer(&addr)`: about 1 run in 40 under load, Alice's home and chat labels stayed refused by the serving node for 90 s and longer; the serving node had no connection and its home label no host, so `host_config` admitted nothing (`owns` needs a label hosted at its own key). The race: Alice's `reach.0` is published by her driver after `create`; pairing right away may copy her account without it.

Question: should a serving node sync with its own host implicitly (one rule: a node that serves is its own first peer), so the `peers add ADDR` step on it goes? Or is the documented step the rule, and a serving node with no saved peer should say so (a diagnostic or `status`) rather than refuse silently?
