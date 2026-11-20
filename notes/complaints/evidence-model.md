# evidence-model
> Summary: Mishaps on the OPEN 10 evidence model branch.

- A python script that replaced "from this marker to the end of the file" in evidence.rs deleted a function appended after it (story_world); caught by the build. Replace between two markers, never to the end.
- held-model's evidence properties judge with a full roles-model walk per reader per step; a story world (about 60 commits) costs about 0.8 CPU-s per unit crossing, so story checks run at tick ends only.
