# conn-policy
- tools/spec_map.py counts a test anchor only when its parenthesis matches a rule name exactly; a line break inside the parenthesis ("(Connection\n// proofs)") becomes a double space and fails as "names no rule". The message doesn't say why.
- Swapping `history::introduce` for contact cards changes the osis-sync suite from ~42 s to ~187 s; the differential worlds are sensitive to how contacts are made, and the default delivery cap (2000) is hit inside `world(0, 4)` before a test can raise it.
