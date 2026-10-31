# reconcile-fp
- Filling a redb label to 2^20 entries one `put` at a time took 12 min (700 µs/put at that size, lazy commits); a bulk-fill path for timing checks would make cap-sized measurements cheap.
