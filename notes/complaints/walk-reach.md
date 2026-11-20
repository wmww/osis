# walk-reach
- Count-test worlds build commit IDs from small integers in several helpers (`chain`, `history`, ad hoc ids): a new world's id collided with `chain`'s `10 + i` at k = 100 and silently replaced a commit. Pick ids from a range no helper uses (or give each helper its own range).
- `tools/mutate.py` with three plants in one build was quick and its per-row log paths made reading each failure easy.
