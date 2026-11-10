# Deleter and uploader judge a delta in two functions
> Summary: Node sync's deleter (`carried`) and uploader (`must_carry`) share delta liveness and the engine's cover test but are separate code: the deleter also requires the covering snapshot present at the host (only makes it wait) and ignores the keep bound for a held delta in a blob that must go, which the uploader counts; a short upload/delete window is suspected while the dropping node's rewrite is on its way (not shown). Property: what a node deletes at a host it would not itself re-upload, as one function. A purged delta within its keep bound must not wait for a carrier, so unifying needs care.
> Priority: low
> Tags: node, sync

Found reviewing reupload-loop (three drifts between the two judgments caused never-settling loops; they are fixed, the split remains). Next step: a test of the suspected keep-bound window, then one function both call.
