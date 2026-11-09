# A removed reader can read the fresh deposit seed of the rotation that removed it
> Summary: A rotation commit is wrapped under the previous read secret (spec/crypto.md §5) and carries the fresh deposit seed in `keys.0`, so a removed reader who still reaches the thing's sync ID at the old head can read it and deposit under the new deposit key. Only a deposit-budget cost; no read of later content.
> Priority: low
> Tags: security, keys, sync

spec/crypto.md §3 says a rotation of the read role MUST write a fresh deposit seed, so a departed holder can no longer deposit. But the rotation commit is wrapped under the epoch it replaces (spec/crypto.md §5 exception) and so open to the removed holder if it reaches the commit under the thing's sync ID before the head moves (`tied::group_admin_*`: Carol, removed through group G, learned the card's new seed through the card's own sync ID; a direct holder likewise). Fix to weigh: seal the seed in the rotation's boxes rather than in `keys.0`, or state that the deposit seed is not kept from departed readers and drop the MUST.
