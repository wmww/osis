#!/bin/sh
# One box's side of a dogfood build update (notes/dogfood.md, Update the build).
#   tools/dogfood-member.sh build PIN                  in a claimed worktree: build osis-cli at PIN into ~/osis-dogfood/bin/osis-SHORT
#   tools/dogfood-member.sh host PIN LISTEN            the shared node: new store host-SHORT, its card and account, its daemon listening at LISTEN (quic://IP:PORT)
#   tools/dogfood-member.sh create NAME PIN ADDR HOST  new own store NAME-SHORT dialing ADDR (URL#KEY), a new channel, its link,
#                                                      `chat relay` to the shared node's account (HOST: its host-SHORT dir copied here, or card and account files)
#   tools/dogfood-member.sh accept PIN CHAT K          on the shared node: keep the channel and K unread (lists the invitations, accepts both)
#   tools/dogfood-member.sh join NAME PIN ADDR LINK    new own store NAME-SHORT dialing ADDR, joined by LINK through the shared node
# Store dirs keep address, chat, k, link, cursor (members) or card, account, address (host): never commit them.
set -eu
DF="$HOME/osis-dogfood"
cmd=$1; shift
short() { git rev-parse --short=9 "$1"; }
need() { [ -x "$1" ] || { echo "no $1: run build first" >&2; exit 1; }; }
fresh() { [ -e "$1" ] && { echo "$1 exists" >&2; exit 1; }; mkdir -m 700 "$1"; }
# the daemon starts only after every direct command on the store has ended
daemon() { systemd-run --user --unit "$1" "$2" -s "$3/store" --dial "$4" serve >/dev/null; }
case $cmd in
build)
	pin=$1
	# it detaches HEAD: never in the main checkout
	[ "$(git rev-parse --git-dir)" != "$(git rev-parse --git-common-dir)" ] || { echo "build only in a claimed worktree (wt claim)" >&2; exit 1; }
	git checkout -q --detach "$pin"
	cargo build -p osis-cli --bin osis
	mkdir -p "$DF/bin"
	cp target/debug/osis "$DF/bin/osis-$(short "$pin")"
	echo "$DF/bin/osis-$(short "$pin")"
	;;
host)
	pin=$1 listen=$2; s=$(short "$pin"); bin="$DF/bin/osis-$s"; dir="$DF/host-$s"
	need "$bin"; fresh "$dir"
	"$bin" -s "$dir/store" init >/dev/null
	"$bin" -s "$dir/store" whoami | awk '$1 == "me" { print $2 }' > "$dir/account"
	# card commands do not run through a daemon: before it starts
	"$bin" -s "$dir/store" card show > "$dir/card"
	systemd-run --user --unit "osis-dogfood-host-$s" "$bin" -s "$dir/store" serve --listen "$listen" >/dev/null
	# its first line is the address, once it listens
	i=0
	until journalctl --user -u "osis-dogfood-host-$s" -o cat | grep -m1 '#' > "$dir/address"; do
		i=$((i + 1))
		[ "$i" -lt 30 ] || { echo "no address yet: journalctl --user -u osis-dogfood-host-$s" >&2; exit 1; }
		sleep 1
	done
	echo "$dir"
	;;
create)
	name=$1 pin=$2 addr=$3 host=$4; s=$(short "$pin"); bin="$DF/bin/osis-$s"; dir="$DF/$name-$s"
	need "$bin"; fresh "$dir"
	printf %s "$addr" > "$dir/address"
	o() { "$bin" -s "$dir/store" --dial "$addr" --timeout 60s "$@"; }
	"$bin" -s "$dir/store" init >/dev/null
	o card import "$(cat "$host/card")" >/dev/null
	o chat create --name channel > "$dir/chat"
	c=$(cat "$dir/chat")
	o chat link "$c" > "$dir/link"
	o link ls "$c" | awk '{ print $1 }' > "$dir/k"
	o chat relay "$c" "$(cat "$host/account")" >/dev/null
	"$bin" -s "$dir/store" --json chat read "$c" | tail -n 1 | sed 's/.*"cursor":"\([^"]*\)".*/\1/' > "$dir/cursor"
	daemon "osis-$name-$s" "$bin" "$dir" "$addr"
	echo "$dir"
	;;
accept)
	pin=$1 c=$2 k=$3; s=$(short "$pin"); bin="$DF/bin/osis-$s"; dir="$DF/host-$s"
	# both must be invitations here first: one whose grant has not arrived accepts nothing
	"$bin" -s "$dir/store" invitations
	"$bin" -s "$dir/store" accept "$c" "$k"
	"$bin" -s "$dir/store" status
	;;
join)
	name=$1 pin=$2 addr=$3 link=$4; s=$(short "$pin"); bin="$DF/bin/osis-$s"; dir="$DF/$name-$s"
	need "$bin"; fresh "$dir"
	printf %s "$addr" > "$dir/address"
	o() { "$bin" -s "$dir/store" --dial "$addr" --timeout 120s "$@"; }
	"$bin" -s "$dir/store" init >/dev/null
	o chat join "$link" > "$dir/chat"
	o --json chat read "$(cat "$dir/chat")" | tail -n 1 | sed 's/.*"cursor":"\([^"]*\)".*/\1/' > "$dir/cursor"
	daemon "osis-$name-$s" "$bin" "$dir" "$addr"
	echo "$dir"
	;;
*) echo "usage: see the header" >&2; exit 2 ;;
esac
