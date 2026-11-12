#!/bin/sh
# One coordinator's side of a dogfood build update (notes/dogfood.md, Update the build).
#   tools/dogfood-member.sh build PIN              in a claimed worktree: build osis-cli at PIN into ~/osis-dogfood/bin/osis-SHORT
#   tools/dogfood-member.sh create NAME PIN URL    new own store NAME-SHORT synced through URL, a new channel chat, its link
#   tools/dogfood-member.sh join NAME PIN URL LINK new own store NAME-SHORT synced through URL, joined by LINK
# The store dir keeps address, chat, link and cursor files: never commit them.
set -eu
DF="$HOME/osis-dogfood"
cmd=$1; shift
case $cmd in
build)
	pin=$1; short=$(git rev-parse --short=9 "$pin")
	git checkout -q --detach "$pin"
	cargo build -p osis-cli --bin osis
	mkdir -p "$DF/bin"
	cp target/debug/osis "$DF/bin/osis-$short"
	echo "$DF/bin/osis-$short"
	;;
create|join)
	name=$1 pin=$2 url=$3; short=$(git rev-parse --short=9 "$pin")
	bin="$DF/bin/osis-$short"; dir="$DF/$name-$short"
	[ -x "$bin" ] || { echo "no $bin: run build first" >&2; exit 1; }
	[ -e "$dir" ] && { echo "$dir exists" >&2; exit 1; }
	mkdir -m 700 "$dir"
	printf %s "$url" > "$dir/address"
	"$bin" -s "$dir/store" init --peer "$url" >/dev/null
	if [ "$cmd" = create ]; then
		"$bin" -s "$dir/store" chat create --name channel > "$dir/chat"
		"$bin" -s "$dir/store" chat link "$(cat "$dir/chat")" > "$dir/link"
	else
		"$bin" -s "$dir/store" chat join "$4" > "$dir/chat"
	fi
	# the daemon starts only after every direct command on the store has ended
	systemd-run --user --unit "osis-$name-$short" "$bin" -s "$dir/store" serve >/dev/null
	sleep 2
	"$bin" -s "$dir/store" --json chat read "$(cat "$dir/chat")" | tail -n 1 | sed 's/.*"cursor":"\([^"]*\)".*/\1/' > "$dir/cursor"
	echo "$dir"
	;;
*) echo "usage: see the header" >&2; exit 2 ;;
esac
