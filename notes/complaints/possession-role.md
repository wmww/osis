# possession-role
> Summary: workflow notes from the possession-at-role-needed branch.

- Two test helpers named `rotate_unchecked` (tests_members, and the one wanted for tests_possession): the engine's `rotate_leaving_out` test helper swallows commit errors (`let _ =`), so a rotation the writer rules refuse silently makes nothing; a test relying on it can pass vacuously unless it counts the commits made.
