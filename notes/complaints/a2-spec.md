# Complaints: a2-spec
> Summary: Workflow snags met writing stage A2 into spec/.

- An unquoted heredoc ate backticked aspect names (`sync.0`) as command substitutions; quote heredocs (`<<'EOF'`) whenever the text holds backticks.
