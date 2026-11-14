# memo-effects (review)
- Rebase onto main conflicted in held.rs: forged-edges added a `granted` map stamped with the old one-for-all `rest_read`; resolved as a per-key `Row::Granted` stamp. A branch that changes how a container stamps should expect every new map on it from main to need its own key.
