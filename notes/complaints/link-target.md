# link-target review
- `World::step` is the only way to stop a maker's upload at a point; a test's step counts name no event, so a change of upload order makes such a test pass without testing anything. A hook "stop after blob kind X reached the host" would help.
