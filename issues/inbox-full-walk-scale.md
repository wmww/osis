# A full pass of a home label walks every inbox blob
> Summary: `inbox_certificates` costs about 13 µs a blob in a full pass (release; 100 µs more the first time after a role write), flat in things held; ordinary passes skip copied blobs. A hostile contact's stamped blobs, up to the host's label caps, still make each full pass of that home label long.
> Tags: node-sync, performance, security

`may_read` is flat in things held (`Memo::roles_now`). A bound on a connected sender's blobs would close it. `vet_inbox_hints` also walks every blob, at 0.25-0.5 ms per 640.
