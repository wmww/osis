# Past the cap, two owner epochs with one secret derive one epoch
> Summary: above 2^62 two owner epochs carrying the same secret at different n derive to one derived epoch (`derived_n` caps n), the last processed wins; a holder of that secret can plant an unestablished copy and leave a plain thing's derived epoch unestablished. Insider-only disruption (no secret leaks; such an insider can rotate anyway). Low.
> Tags: security, keys

Found reviewing epoch-cap-order (round 13 item 121). Direction: derive from the established owner epoch only, or key the derived map by (order, nonce).
