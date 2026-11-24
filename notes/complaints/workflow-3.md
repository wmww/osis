# workflow-3
> Summary: A test edit sent as a nested heredoc ran its body in the worktree and pushed to the real main.

- A Bash call wrote a Python edit script by `python3 - <<'EOF'` whose text held the test's own `<<'EOF'` block: the inner `EOF` line ended the outer heredoc, and bash ran the rest (the test's setup lines) in the worktree, including `git checkout --detach origin/main`, `git add -A`, `git commit` and `git push origin HEAD:main`, which pushed a fixture commit to the real main (reverted at once). Write edit scripts with the Write tool and run them as a file; never nest heredocs, and a shell test's fixtures go in printf lines, not heredocs (tools/merge_branch_test.sh now also stops unless its origin is its temp remote).
