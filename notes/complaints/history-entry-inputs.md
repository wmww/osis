# history-entry-inputs
- The open = rebuild index check (`apply::keys::tests::*leaves_thing_plain*`) was the only thing that caught seeds of the record from a derived view (`refresh_own_keys` regain) not followed by a whole read of the state; the panic prints whole `ActorEpochs` on one line, so finding the differing field took a throwaway diff script.
- A redirect into a scratch dir that did not exist yet failed silently inside a backgrounded command (exit 1, no output): create the directory first.
