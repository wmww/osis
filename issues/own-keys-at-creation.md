# A root made under the account gets no own keys at creation
> Summary: The plan says a new root made under the account (a chat, a shared tag) gets its own keys at creation and is held by ticket, but the `osis` API gives a thing own keys only at its first grant or link. A chat made by `osis_chat::create` is under the account, held by a strong from home or the account root, and in no sync unit until then: it stays on the node that made it (`osis-chat` `a_chat_made_and_joined_syncs_spec_sync_set_4` fails at the maker's other node).
> Priority: normal
> Tags: engine, api, chat

- The engine has the mechanism (`rotation::own_secrets`, `Engine::mint_actor` for a client's actor); the public API does not reach it, and the plan says it should have no notion of own keys.
- One rule that keeps that: a thing made directly under an account (a key actor, so in no sync unit) gets own keys in its creating transaction, always. Cost: about 2.6 KB of keys and a sync ID per such thing, and every test helper that makes things with `create()` under the account pays it (about 700 engine tests make things with no strong today: issues/reference-graph.md Status).
- Made under the account root instead, the chat syncs to the account's nodes at once and gets own keys at its first grant, but its first admin is then the account root, which every participant's chain names: not what the plan chose.
- Marked `// refgraph:` in libs/chat/src/lib.rs `create`.
