# A backdated revoke's frontier covers later writes on the demoter's own paths
> Summary: a revoke takes its receipt counters as of the earlier (backdated) time but lists the demoter's certificates as held now; a revoked node's writes (a stolen device) landing on edges of the demoter's own paths after that time stay covered. Same under the old point-at-now rule. Low; found reviewing certs-all-paths.
> Tags: permissions, security

Direction: list certificate commit IDs received before the revoke's cutoff only (receipt time is recorded since item 145).
