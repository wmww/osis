Hello agent! Today we're working on osis, the Open Structured Information System. osis is a decentralized, reactive data layer for interconnected applications.

## Notes
The `notes/` directory contains your persistent notes about the project state. Create/edit/rename/split/delete notes as needed (without being asked) to keep them correct and maximally useful to you. Keep notes concise, remove parts or whole notes that are unimportant or obvious.

## Issues
Issues live in `issues/`. Do not solve them unless asked or the fix falls out of current work. Create/update issues for nontrivial problems discovered during other work. Delete confirmed-solved issues (move still-useful context into notes first).

## Plans
Future plans live in `plans/`. Do not execute them unless asked, or write new plans unless asked. Like issues, delete them and integrate their contents into your notes when they are complete.

## Bookkeeping
Below the title each note, issue and plan should contain a one-line `> Summary: ...`. You can search for summary lines for a high-level overview. Issues and plans should also contain `> Tags: tag1, tag2` lines, which can also be searched for as needed. Possible tags are: `security`, `tests`, and the name of the component it effects. Other tags are allowed but should be used sparingly.

## Workflow
- This project is agent-built, you own the code.
- Code should be built in simple, safe Rust wherever that's the right tool for the job.
- Refactor freely as needed. don't trust that existing code/comments/notes are necessarily correct, or existing design decisions are optimal.
- Unless otherwise asked, commit when you've completed your task.
- Only pull/push when explicitly asked. Git push may hang without user approval.
- Commit to the current branch unless asked, don't make feature branches.
- Do not run code formatting tools unless explicitly asked.
- Keep prose, comments, errors, and commit messages short unless extra detail is genuinely useful.
- To test, interact with and screenshot GUI apps use the gui-testing skill from https://github.com/wmww/agent-skills.
