#!/usr/bin/env bash
# End-to-end smoke test of the wire protocol (docs/PROTOCOL.md) with
# nothing but nc, jq and the age CLI: proof that a non-Go client needs
# no library. Starts keycelld on a temporary socket and data dir, walks
# all seven methods, stops the daemon with SIGTERM and cleans up.
#
# usage: scripts/protocol-smoke.sh [keycelld-binary]
set -euo pipefail

for tool in nc age age-keygen jq; do
	command -v "$tool" >/dev/null || { echo "missing tool: $tool" >&2; exit 2; }
done

ROOT=$(cd "$(dirname "$0")/.." && pwd)
TMP=$(mktemp -d)
PID=""
cleanup() {
	if [[ -n $PID ]] && kill -0 "$PID" 2>/dev/null; then
		kill -TERM "$PID"
		wait "$PID" || true
	fi
	rm -rf "$TMP"
}
trap cleanup EXIT

BIN=${1:-}
if [[ -z $BIN ]]; then
	BIN=$TMP/keycelld
	(cd "$ROOT" && go build -o "$BIN" ./cmd/keycelld)
fi

DATA=$TMP/data
SOCK=$TMP/keycell.sock
mkdir -p "$DATA"
age-keygen -o "$TMP/identity.txt" 2>/dev/null
PUB=$(age-keygen -y "$TMP/identity.txt")
printf '{"version":1,"secrets":{}}' | age -r "$PUB" -o "$DATA/vault.age"
IDENTITY=$(grep '^AGE-SECRET-KEY-1' "$TMP/identity.txt" | tr -d '\n' | base64 -w0)

"$BIN" --socket "$SOCK" --data-dir "$DATA" --auto-lock 0 --log-level warn 2>"$TMP/daemon.log" &
PID=$!
for _ in $(seq 50); do
	[[ -S $SOCK ]] && break
	sleep 0.1
done
[[ -S $SOCK ]] || { echo "daemon did not listen on $SOCK" >&2; cat "$TMP/daemon.log" >&2; exit 1; }

FAILED=0
call() { printf '%s\n' "$1" | nc -U -N "$SOCK"; }
check() {
	local name=$1 resp=$2 expr=$3
	if jq -e "$expr" <<<"$resp" >/dev/null 2>&1; then
		echo "ok   $name"
	else
		echo "FAIL $name: $resp"
		FAILED=1
	fi
}

NAME=smoke/test
VALUE=$(printf 'hello' | base64 -w0)

check "status locked"   "$(call '{"id":1,"method":"status"}')" '.id==1 and .result.protocol==1 and .result.locked==true'
check "unlock"          "$(call '{"id":2,"method":"unlock","params":{"identity":"'"$IDENTITY"'"}}')" '.result=={}'
check "store"           "$(call '{"id":3,"method":"store","params":{"name":"'"$NAME"'","kind":"generic","attributes":{"env":"smoke"},"value":"'"$VALUE"'"}}')" '.result=={}'
check "list"            "$(call '{"id":4,"method":"list"}')" '.result|length==1 and .[0].name=="'"$NAME"'" and .[0].kind=="generic" and (.[0]|has("value")|not)'
check "get"             "$(call '{"id":5,"method":"get","params":{"name":"'"$NAME"'"}}')" '.result.value=="'"$VALUE"'" and .result.attributes.env=="smoke"'
check "delete"          "$(call '{"id":6,"method":"delete","params":{"name":"'"$NAME"'"}}')" '.result=={}'
check "get NOT_FOUND"   "$(call '{"id":7,"method":"get","params":{"name":"'"$NAME"'"}}')" '.error.code=="NOT_FOUND"'
check "lock"            "$(call '{"id":8,"method":"lock"}')" '.result=={}'
check "status relocked"  "$(call '{"id":9,"method":"status"}')" '.result.locked==true and (.result|has("locks_at")|not)'
check "get LOCKED"      "$(call '{"id":10,"method":"get","params":{"name":"'"$NAME"'"}}')" '.error.code=="LOCKED"'
check "broken json"     "$(call '{"id":11,"method":')" '.id==null and .error.code=="PROTOCOL"'

kill -TERM "$PID"
if wait "$PID"; then
	echo "ok   SIGTERM exit 0"
else
	echo "FAIL SIGTERM exit $?"
	FAILED=1
fi
PID=""
if [[ -e $SOCK ]]; then
	echo "FAIL socket still present"
	FAILED=1
else
	echo "ok   socket removed"
fi

if [[ $FAILED -ne 0 ]]; then
	echo "--- daemon log" >&2
	cat "$TMP/daemon.log" >&2
	exit 1
fi
echo "all checks passed"
