# chat-polish
- Tier 1 took about 10 min wall at load 36-38 (osis-node `it` 153 s, documented ~40 s warm for the whole run); tier 1 + clippy + app build in one background call came to 18 min.
- The brief said `osis chat` might list chats: it has no list command, so nothing to change in cli/.
- Review: `claudewait ID || <fallback path> ID` reran claudewait after its exit 124 (still running) instead of only on a missing command, and hit the tool timeout; call it bare. Gate took 830 s at load ~16-28.
