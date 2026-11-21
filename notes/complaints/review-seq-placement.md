# review-seq-placement
- The property's two "placement kept" panics (placement dropped vs. held but its stored rows missing) share one text, so a known_failures pattern for the fallback also hid the second, which would be a lost-row bug; patterns had to key on the `(writer` suffix. Distinct panic texts per failure kind would keep patterns narrow.
