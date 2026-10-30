# eph-unpaged-cover
- Two background cargo runs started together (tier-2 oracle and sim sweep) serialize on the build lock; harmless, but the sim sweep's 5 min ran alongside the 10 min oracle at full CPU.
