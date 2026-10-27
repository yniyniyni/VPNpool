#!/bin/sh
# vpnpool: the GeoIP lists of the Routes page -> local sing-box rule-sets (called by build.sh).
#
#   uci vpnpool.routing:  geoip_source  loyalsoldier (default) | v2fly | url
#                         geoip_url     a geoip.dat to take the codes from (geoip_source url)
#                         list geoip    codes: ru, private, telegram, ru-blocked, ...
#   -> $SB_DATA/geoip/<code>.srs (sing-box binary) | <code>.json (rule-set source); generator.uc
#      gives sing-box every file that is there, as a LOCAL rule-set. Local on purpose: a remote
#      rule-set sing-box can't download (a typo in a code = 404) stops sing-box at start; here a
#      bad code is only skipped, and the status says why.
#   -> $SB_DATA/geoip_status.json {at, source, codes: {<code>: {ok, n?, cached?, error?}}}
#      error: not_found | fetch_failed | bad_file | reverse_match | empty | low_memory | no_url
#
# Where from:
#   loyalsoldier  Loyalsoldier/geoip, branch release: srs/<code>.srs (ready-made for sing-box;
#                 countries + services: telegram, google, netflix, cloudflare, ...)
#   v2fly         v2fly/geoip, branch release: text/<code>.txt (a CIDR list; countries + private)
#                 -> geoip.uc text
#   url           any v2ray geoip.dat (Loyalsoldier, v2fly, runetfreedom ru-blocked ...) -> geoip.uc
#                 dat: only the codes asked for are decoded
# raw.githubusercontent.com first, then the jsDelivr mirror (not for a .dat: jsDelivr serves at
# most 20 MB); each first directly, then through the tunnel (our sing-box's local SOCKS port)
# when the direct way gets no answer. A 404 is an answer: the code does not exist.
#
# Fresh for GEOIP_TTL (24 h): a build within it does no download. The set (source, URL, codes)
# changed -> downloaded at once. Kept in flash too ($CONF_DIR/geoip, rewritten only when a file
# changed): after a reboot the lists are there before the network is. A code whose download
# failed keeps its last good copy (cached: true). A failed download (no answer) is tried again on
# the next build; a code that does not exist is not looked up again until the TTL ends.
. /usr/libexec/vpnpool/lib.sh

OUT="$SB_DATA/geoip"
CACHE="$CONF_DIR/geoip"
STATUS="$SB_DATA/geoip_status.json"
WORK="$SB_DATA/.geoip.new"
GEOIP_TTL=${VPNPOOL_GEOIP_TTL:-86400}
LS_BASES="https://raw.githubusercontent.com/Loyalsoldier/geoip/release https://cdn.jsdelivr.net/gh/Loyalsoldier/geoip@release"
V2_BASES="https://raw.githubusercontent.com/v2fly/geoip/release https://cdn.jsdelivr.net/gh/v2fly/geoip@release"
# the size limit of one download: a list of one code is far below 8 MB; a whole geoip.dat
# (16-23 MB today) up to geoip_max_mb (my limit)
LIST_MAX=$((8 * 1024 * 1024))
DAT_MAX_MB=$(uci -q get vpnpool.main.geoip_max_mb); case "$DAT_MAX_MB" in ''|*[!0-9]*) DAT_MAX_MB=48 ;; esac
MEMINFO=${VPNPOOL_MEMINFO:-/proc/meminfo}

SRC=$(uci -q get vpnpool.routing.geoip_source); case "$SRC" in loyalsoldier|v2fly|url) ;; *) SRC=loyalsoldier ;; esac
URL=$(uci -q get vpnpool.routing.geoip_url)
CODES=""
for c in $(uci -q get vpnpool.routing.geoip); do
	case "$c" in *[!a-z0-9_-]*|[!a-z0-9]*) continue ;; esac
	case " $CODES " in *" $c "*) ;; *) CODES="$CODES $c" ;; esac
done
CODES=${CODES# }
SIG="$SRC|$URL|$CODES"

if [ -z "$CODES" ]; then
	rm -rf "$OUT" "$CACHE" "$WORK"
	printf '{"at":%s,"source":"%s","codes":{}}\n' "$(date +%s)" "$SRC" | write_atomic "$STATUS"
	exit 0
fi

age_of() { local m; m=$(date -r "$1" +%s 2>/dev/null) || { echo 999999999; return; }; echo $(( $(date +%s) - m )); }
# fresh in RAM: nothing to do
if [ "$(cat "$OUT/.sig" 2>/dev/null)" = "$SIG" ] && [ "$(age_of "$OUT/.sig")" -lt "$GEOIP_TTL" ]; then exit 0; fi
# after a reboot: the flash copy, if it is of this set and fresh
if [ ! -d "$OUT" ] && [ "$(cat "$CACHE/.sig" 2>/dev/null)" = "$SIG" ] && [ "$(age_of "$CACHE/.sig")" -lt "$GEOIP_TTL" ]; then
	rm -rf "$WORK"; mkdir -p "$WORK" && cp -p "$CACHE"/* "$CACHE/.sig" "$WORK"/ 2>/dev/null
	rm -rf "$OUT"; mv "$WORK" "$OUT"
	[ -s "$STATUS" ] || cp "$CACHE/.status.json" "$STATUS" 2>/dev/null
	log "geoip: lists from the flash copy ($CODES)"
	exit 0
fi

# get <url> <file> <max bytes> -> prints the HTTP code ("000": no answer); 0 = 200 and a body
get() {
	local code
	rm -f "$2"
	code=$(curl -sL --connect-timeout 5 -m "${TMO:-30}" --max-filesize "$3" -o "$2" -w '%{http_code}' "$1" 2>/dev/null)
	if { [ -z "$code" ] || [ "$code" = 000 ]; } && [ -n "$(our_singbox_pids)" ]; then
		code=$(curl -sL --connect-timeout 5 -m "${TMO:-30}" --max-filesize "$3" --proxy "socks5h://127.0.0.1:$TG_TEST_PORT" \
			-o "$2" -w '%{http_code}' "$1" 2>/dev/null)
	fi
	echo "${code:-000}"
	[ "$code" = 200 ] && [ -s "$2" ] && return 0
	rm -f "$2"   # an error page is not a list
	return 1
}
# from_bases <bases> <path> <file> -> 0 got it | 1 not found (404 everywhere) | 2 no answer
from_bases() {
	local b code nf=0
	for b in $1; do
		code=$(get "$b/$2" "$3" "$LIST_MAX") && return 0
		[ "$code" = 404 ] && nf=1
	done
	[ "$nf" = 1 ] && return 1
	return 2
}

rm -rf "$WORK"; mkdir -p "$WORK"
RES="$WORK/.res"; : > "$RES"   # code \t ok|error \t n
retry=0
note() { printf '%s\t%s\t%s\n' "$1" "$2" "${3:-}" >> "$RES"; [ "$2" = fetch_failed ] && retry=1; return 0; }

case "$SRC" in
loyalsoldier)
	for c in $CODES; do
		from_bases "$LS_BASES" "srs/$c.srs" "$WORK/$c.srs"
		case $? in
			0) if [ "$(head -c 3 "$WORK/$c.srs")" = SRS ]; then note "$c" ok; else rm -f "$WORK/$c.srs"; note "$c" bad_file; fi ;;
			1) note "$c" not_found ;;
			*) note "$c" fetch_failed ;;
		esac
	done ;;
v2fly)
	for c in $CODES; do
		from_bases "$V2_BASES" "text/$c.txt" "$WORK/$c.txt"
		case $? in
			0) r=$(ucode /usr/libexec/vpnpool/geoip.uc text "$WORK/$c.txt" "$WORK/$c.json" 2>/dev/null)
			   if printf '%s' "$r" | jq -e '.ok' >/dev/null 2>&1; then note "$c" ok "$(printf '%s' "$r" | jq -r .n)"
			   else note "$c" "$(printf '%s' "$r" | jq -r '.error // "bad_file"' 2>/dev/null)"; fi
			   rm -f "$WORK/$c.txt" ;;
			1) note "$c" not_found ;;
			*) note "$c" fetch_failed ;;
		esac
	done ;;
url)
	if [ -z "$URL" ]; then
		for c in $CODES; do note "$c" no_url; done
	else
		TMO=180 code=$(get "$URL" "$WORK/.geoip.dat" $((DAT_MAX_MB * 1024 * 1024)))
		if [ "$code" = 200 ] && [ -s "$WORK/.geoip.dat" ]; then
			# the parser holds the whole file in memory: it must fit twice over, with room to spare
			sz=$(( $(wc -c < "$WORK/.geoip.dat") / 1024 ))
			ma=$(awk '$1 == "MemAvailable:" { print $2 }' "$MEMINFO" 2>/dev/null)
			if [ -n "$ma" ] && [ "$ma" -lt $(( sz * 2 + 16384 )) ]; then
				for c in $CODES; do note "$c" low_memory; done
			else
				# shellcheck disable=SC2086
				r=$(ucode /usr/libexec/vpnpool/geoip.uc dat "$WORK/.geoip.dat" "$WORK" $CODES 2>/dev/null)
				for c in $CODES; do
					if printf '%s' "$r" | jq -e --arg c "$c" '.codes[$c].ok' >/dev/null 2>&1; then
						note "$c" ok "$(printf '%s' "$r" | jq -r --arg c "$c" '.codes[$c].n')"
					else
						note "$c" "$(printf '%s' "$r" | jq -r --arg c "$c" '.codes[$c].error // .error // "bad_file"' 2>/dev/null)"
					fi
				done
			fi
		elif [ "$code" = 404 ]; then for c in $CODES; do note "$c" not_found; done
		else for c in $CODES; do note "$c" fetch_failed; done
		fi
		rm -f "$WORK/.geoip.dat"
	fi ;;
esac

# a code that failed keeps its last good copy of the same source (the flash copy)
csrc=$(cut -d'|' -f1,2 "$CACHE/.sig" 2>/dev/null)
: > "$WORK/.res2"
while IFS="$(printf '\t')" read -r c st n; do
	if [ "$st" != ok ] && [ "$csrc" = "$SRC|$URL" ]; then
		for f in "$CACHE/$c.srs" "$CACHE/$c.json"; do
			[ -s "$f" ] && cp -p "$f" "$WORK/" && st=cached && break
		done
	fi
	printf '%s\t%s\t%s\n' "$c" "$st" "$n" >> "$WORK/.res2"
done < "$RES"
jq -Rn --argjson at "$(date +%s)" --arg src "$SRC" '
	{at: $at, source: $src, codes: (reduce (inputs | split("\t")) as $r ({};
		.[$r[0]] = (if $r[1] == "ok" then {ok: true} + (if ($r[2] // "") != "" then {n: ($r[2] | tonumber)} else {} end)
		            elif $r[1] == "cached" then {ok: true, cached: true}
		            else {ok: false, error: $r[1]} end)))}' "$WORK/.res2" | write_atomic "$STATUS"
rm -f "$RES" "$WORK/.res2"

# no answer for some code: no .sig, so the next build tries again
[ "$retry" = 0 ] && echo "$SIG" > "$WORK/.sig"
rm -rf "$OUT"; mv "$WORK" "$OUT"

# the flash copy: the files that changed, the ones no longer wanted go
mkdir -p "$CACHE"
for f in "$OUT"/*.srs "$OUT"/*.json; do [ -f "$f" ] && persist_if_changed "$f" "$CACHE/${f##*/}"; done
for f in "$CACHE"/*.srs "$CACHE"/*.json; do [ -f "$f" ] && [ ! -f "$OUT/${f##*/}" ] && rm -f "$f"; done
[ -f "$OUT/.sig" ] && persist_if_changed "$OUT/.sig" "$CACHE/.sig"
persist_if_changed "$STATUS" "$CACHE/.status.json"
log "geoip: $SRC: $(jq -r '[.codes | to_entries[] | "\(.key) \(if .value.ok then (if .value.cached then "cached" else "ok" end) else .value.error end)"] | join(", ")' "$STATUS" 2>/dev/null)"
exit 0
