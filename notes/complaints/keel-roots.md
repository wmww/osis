# keel-roots
- The final review's "engine default tests pass" for narrowing the key-actor root was not checked: 76 engine tests failed, because a sibling node is kept by no need (D bears no edge write and its `holds.0` strongs only the creating node). Took a probe in `settle` to see which key actors went and why.
- R2 could not reach a paged-state join bug at all: its scan reads every state whole (`Engine::get`), so every later join met a fully loaded cache. Paged-state oracles need the state evicted (`Tx::evict_pages`) between checks.
- osis test `deliver` ingests without ending a pass, so arrivals are judged whenever the next pass end happens, possibly inside a measured window.
