# keel-prose-2days
- The brief's "don't touch issues/reference-graph.md" clashes with policy.py: merging a note it points at fails the baseline until its pointer is fixed. A one-line pointer edit there was the only way to pass.
- "Every other note with more than 5 commits in 2 days" is about 40 notes (~500 KB) on top of the 13 named: far past one prose pass. Briefs for this job should name the files.
- A backticked-identifier check (grep each `name` against the sources) found dead test pointers cheaply; worth a tools/ script.
