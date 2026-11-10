# net-reconnect-b
- `Net` cannot build a holder that the other node judges unknown (J needs the holder's account roster missing at the judge), so every `until` test is a hand dialer and the stream differential cannot reach `until`. A `Net` helper for "a holder through a roster this node lacks" would let real requesters be tested.
- A mutation run of the `until::` tests (one rule disabled at a time) took about 3 minutes of rebuilds; a small script in the scratch dir did it, worth keeping as a tool.
- `sources::thin_client_over_quic` (osis, networking tier 2) failed once under the heavy lock ("not reached: down", 60 s) and passed on the rerun: flaky, unrelated to the shared set.
