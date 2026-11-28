#!/bin/sh
# One box's side of a dogfood build update (notes/dogfood.md, Update the build).
#   tools/dogfood-member.sh build PIN                  in a claimed worktree: build osis-cli at PIN into ~/osis-dogfood/bin/osis-SHORT
#   tools/dogfood-member.sh host PIN LISTEN            the shared node: new store host-SHORT, its card and account, its daemon listening at LISTEN (quic://IP:PORT)
#   tools/dogfood-member.sh create NAME PIN ADDR HOST  new own store NAME-SHORT dialing ADDR (URL#KEY), a new channel, its link,
#                                                      `chat relay` to the shared node's account (HOST: its host-SHORT dir copied here, or card and account files)
#   tools/dogfood-member.sh accept PIN CHAT K          on the shared node: keep the channel and K unread
#   tools/dogfood-member.sh join NAME PIN ADDR LINK    new own store NAME-SHORT dialing ADDR, joined by LINK through the shared node
#   tools/dogfood-member.sh start NAME PIN             its daemon again after a stop (`systemctl --user stop UNIT`); NAME host: the shared node
# Store dirs keep address, chat, k, link, cursor (members) or card, account, address, listen (host): never commit them.
# Every command runs with --no-lan: members reach the shared node by its address alone, and a node on
# the local network (another build's, a test's) is no one to meet.
# OSIS_DOGFOOD: the state directory (default ~/osis-dogfood); OSIS_DOGFOOD_UNIT: the user units' name prefix
# (default osis): a rehearsal sets both, so it touches neither the real state nor its units.
set -eu
DF="${OSIS_DOGFOOD:-$HOME/osis-dogfood}"
U="${OSIS_DOGFOOD_UNIT:-osis}"
cmd=$1; shift
short() { git rev-parse --short=9 "$1"; }
need() { [ -x "$1" ] || { echo "no $1: run build first" >&2; exit 1; }; }
fresh() { [ -e "$1" ] && { echo "$1 exists" >&2; exit 1; }; mkdir -m 700 "$1"; }
# the daemon starts only after every direct command on the store has ended, and returns once it
# takes clients (its socket line): a command run before would open the store itself and stop it
daemon() {
	t=$(date +%s)
	systemd-run --user --unit "$1" "$2" --no-lan -s "$3/store" --dial "$4" serve >/dev/null
	i=0
	until journalctl --user -u "$1" --since "@$t" -o cat | grep -q '\.sock$'; do
		i=$((i + 1))
		[ "$i" -lt 30 ] || { echo "$1 takes no clients yet: journalctl --user -u $1" >&2; exit 1; }
		sleep 1
	done
	echo "post through it: $2 -s $3/store chat post $(cat "$3/chat" 2>/dev/null || echo CHAT) TEXT" >&2
}
host_daemon() { systemd-run --user --unit "$U-dogfood-host-$1" "$2" --no-lan -s "$3/store" serve --listen "$(cat "$3/listen")" >/dev/null; }
# the cursor of a `chat read` (empty for an empty chat)
cursor() { tail -n 1 | sed -n 's/.*"cursor":"\([^"]*\)".*/\1/p'; }
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
	printf %s "$listen" > "$dir/listen"
	"$bin" --no-lan -s "$dir/store" init >/dev/null
	"$bin" --no-lan -s "$dir/store" whoami | awk '$1 == "me" { print $2 }' > "$dir/account"
	"$bin" --no-lan -s "$dir/store" contact show > "$dir/card"
	host_daemon "$s" "$bin" "$dir"
	# its first line is the address, once it listens
	i=0
	until journalctl --user -u "$U-dogfood-host-$s" -o cat | grep -m1 '#' > "$dir/address"; do
		i=$((i + 1))
		[ "$i" -lt 30 ] || { echo "no address yet: journalctl --user -u $U-dogfood-host-$s" >&2; exit 1; }
		sleep 1
	done
	echo "$dir"
	;;
create)
	name=$1 pin=$2 addr=$3 host=$4; s=$(short "$pin"); bin="$DF/bin/osis-$s"; dir="$DF/$name-$s"
	need "$bin"; fresh "$dir"
	printf %s "$addr" > "$dir/address"
	o() { "$bin" --no-lan -s "$dir/store" --dial "$addr" --timeout 60s "$@"; }
	o init >/dev/null
	o contact import "$(cat "$host/card")" >/dev/null
	o chat create --name channel > "$dir/chat"
	c=$(cat "$dir/chat")
	o chat link "$c" > "$dir/link"
	o link ls "$c" | awk '{ print $1 }' > "$dir/k"
	# exit 6 until the host holds the channel (`accept`): nothing else holds it yet
	o chat relay "$c" "$(cat "$host/account")" >/dev/null || [ $? -eq 6 ]
	o --json chat read "$c" | cursor > "$dir/cursor"
	daemon "$U-$name-$s" "$bin" "$dir" "$addr"
	echo "$dir"
	;;
accept)
	pin=$1 c=$2 k=$3; s=$(short "$pin"); bin="$DF/bin/osis-$s"; dir="$DF/host-$s"
	# holding the channel and K keeps each unread by the sync grant `chat relay` wrote this account
	"$bin" --no-lan -s "$dir/store" hold "$c" "$k"
	"$bin" --no-lan -s "$dir/store" status
	;;
join)
	name=$1 pin=$2 addr=$3 link=$4; s=$(short "$pin"); bin="$DF/bin/osis-$s"; dir="$DF/$name-$s"
	need "$bin"; fresh "$dir"
	printf %s "$addr" > "$dir/address"
	o() { "$bin" --no-lan -s "$dir/store" --dial "$addr" --timeout 120s "$@"; }
	o init >/dev/null
	o chat join "$link" > "$dir/chat"
	o --json chat read "$(cat "$dir/chat")" | cursor > "$dir/cursor"
	daemon "$U-$name-$s" "$bin" "$dir" "$addr"
	echo "$dir"
	;;
start)
	name=$1 pin=$2; s=$(short "$pin"); bin="$DF/bin/osis-$s"; dir="$DF/$name-$s"
	need "$bin"; [ -d "$dir" ] || { echo "no $dir" >&2; exit 1; }
	if [ "$name" = host ]; then host_daemon "$s" "$bin" "$dir"; else daemon "$U-$name-$s" "$bin" "$dir" "$(cat "$dir/address")"; fi
	;;
*) echo "usage: see the header" >&2; exit 2 ;;
esac
