# gate-review
> Summary: Footguns met reviewing and gating the epochs-side + gate-shape stack.
- The gate's held runner read its selection file on stdin and passed that stdin to each step: a step that reads stdin silently ate the later run lines and the gate passed (fixed: `< /dev/null`, tested in gate_select_test.sh).
- The first gate failed at the unification check on a problem from main (issues/gui-build-second-host-set.md) after 16 min of builds at load 25-38; a failing step prints no wall or CPU-s line.
- The unification check passes in a worktree that already holds both artifact sets, so a re-run after a failure is no evidence.
- Local `main` lagged origin/main by four commits; the gate's merge base then pulled other branches' changes into the selection (harmless here: a manifest change selects everything anyway).
