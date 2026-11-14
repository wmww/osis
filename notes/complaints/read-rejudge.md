# read-rejudge
- Finding why an Effects key re-runs had no tool: `memo::Table` had no name and `costs` showed only totals. Now `Effects::due` counts causes (`"<effects> <- <container>"`) while `costs` records; still needs a temporary backtrace probe to name which read of a container (e.g. which `held::Read` variant) moved.
- `read: judged` is both an Effects span name and a `costs::count` in `judge::body`, so its total is twice the judgements (the issue's numbers were doubled).
- The driver's `Engine::follow` calls are untested: every change that moves certificates in today's tests also brings a new commit whose own judgement refreshes the rows, so removing them fails nothing.
