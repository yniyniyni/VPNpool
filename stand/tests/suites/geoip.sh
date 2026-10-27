# suite: geoip — GeoIP lists of the Routes page (sourced by run.sh)
#   geoip.uc   text CIDR list -> rule-set source; geoip.dat (protobuf) -> one source per code
#   geoip.sh   Loyalsoldier .srs / v2fly text / a geoip.dat by URL -> $SB_DATA/geoip, status,
#              mirror, freshness, the saved copy when a download fails, flash copy
#   generator  local rule-sets for the files that are there, the rule after the rules by name
# Offline: every download is the curl test double (mock_rule); the .srs is compiled here by the
# real sing-box; fixtures/geoip/tiny.dat is made by fixtures/geoip/gen.py.

GU=/usr/libexec/vpnpool/geoip.uc
GS=/usr/libexec/vpnpool/geoip.sh
GX="$T_STATE/geoip"; rm -rf "$GX"; mkdir -p "$GX"
TINY="$T_DIR/fixtures/geoip/tiny.dat"
LS=https://raw.githubusercontent.com/Loyalsoldier/geoip/release
LSJ=https://cdn.jsdelivr.net/gh/Loyalsoldier/geoip@release
V2=https://raw.githubusercontent.com/v2fly/geoip/release
cidrs() { jq -c '.rules[0].ip_cidr' "$1" 2>/dev/null; }
# a config with the file as a local rule-set: does sing-box take it?
sb_takes() {   # <file> <binary|source>
	printf '{"route":{"rule_set":[{"type":"local","tag":"g","format":"%s","path":"%s"}],"rules":[{"rule_set":"g","outbound":"direct"}]},"outbounds":[{"type":"direct","tag":"direct"}]}\n' "$2" "$1" > "$GX/c.json"
	sing-box check -c "$GX/c.json" >/dev/null 2>&1
}
geo_set() {   # <source> <url> <codes...>
	local src=$1 url=$2; shift 2
	uci -q delete vpnpool.routing.geoip
	uci set vpnpool.routing.geoip_source="$src"; uci set vpnpool.routing.geoip_url="$url"
	for c in "$@"; do uci add_list vpnpool.routing.geoip="$c"; done
	uci commit vpnpool
}
gst() { jq -c --arg c "$1" '.codes[$c]' /tmp/vpnpool/geoip_status.json 2>/dev/null; }

# ---- geoip.uc text ----
printf '# a comment\n\n198.51.100.0/24\n 203.0.113.7 \n2001:db8::/32\n2001:db8::1\nnot an address\n300.1.1.1/24\n198.51.100.0/40\n' > "$GX/l.txt"
_r=$(ucode $GU text "$GX/l.txt" "$GX/l.json" 2>/dev/null)
begin "geoip/uc-text-to-rule-set-source"
expect_jq "ok, 4 networks" "$_r" '.ok==true and .n==4'
expect_eq "the CIDRs, bare addresses as /32 and /128, junk skipped" "$(cidrs "$GX/l.json")" '["198.51.100.0/24","203.0.113.7/32","2001:db8::/32","2001:db8::1/128"]'
expect_jq "a version-2 source" "$(cat "$GX/l.json")" '.version==2 and (.rules|length)==1'
expect_true "sing-box takes it" sb_takes "$GX/l.json" source
end
printf '# nothing\nfoo\n' > "$GX/e.txt"
begin "geoip/uc-text-without-addresses"
expect_jq "empty" "$(ucode $GU text "$GX/e.txt" "$GX/e.json" 2>/dev/null)" '.ok==false and .error=="empty"'
expect_true "no file" [ ! -e "$GX/e.json" ]
end

# ---- geoip.uc dat ----
mkdir -p "$GX/d"
_r=$(ucode $GU dat "$TINY" "$GX/d" ru AD xx rev empty nosuch 2>/dev/null)
begin "geoip/uc-dat-only-the-codes-asked-for"
expect_jq "ru: 4 networks" "$_r" '.codes.ru == {ok:true, n:4}'
expect_eq "ru: IPv4 and IPv6, in the file's order" "$(cidrs "$GX/d/ru.json")" '["198.51.100.0/24","203.0.113.0/25","2001:db8:0:0:0:0:0:0/32","2001:db8:abcd:12:0:0:0:0/64"]'
expect_jq "AD (asked in capitals): found, written under the name asked for" "$_r" '.codes.AD == {ok:true, n:1}'
expect_true "AD.json" [ -s "$GX/d/AD.json" ]
expect_eq "xx: the code after its addresses still counts" "$(cidrs "$GX/d/xx.json")" '["203.0.113.128/25"]'
expect_jq "rev: reverse_match refused" "$_r" '.codes.rev == {ok:false, error:"reverse_match"}'
expect_jq "empty: empty" "$_r" '.codes.empty == {ok:false, error:"empty"}'
expect_jq "nosuch: not_found" "$_r" '.codes.nosuch == {ok:false, error:"not_found"}'
expect_true "no file for the refused codes" sh -c '[ ! -e "$1/rev.json" ] && [ ! -e "$1/empty.json" ] && [ ! -e "$1/nosuch.json" ]' _ "$GX/d"
expect_true "sing-box takes ru" sb_takes "$GX/d/ru.json" source
end
printf 'no protobuf here at all' > "$GX/bad.dat"
begin "geoip/uc-dat-not-a-geoip-dat"
expect_jq "bad_file" "$(ucode $GU dat "$GX/bad.dat" "$GX/d" ru 2>/dev/null)" '.ok==false and .error=="bad_file"'
end

# ---- geoip.sh ----
printf '{"version":2,"rules":[{"ip_cidr":["198.51.100.0/24"]}]}\n' > "$GX/src.json"
sing-box rule-set compile --output "$GX/ru.srs" "$GX/src.json" >/dev/null 2>&1
printf '<html>rate limited</html>\n' > "$GX/html.txt"
printf '198.51.100.0/24\n2001:db8::/32\n' > "$GX/v2ru.txt"
geo_run() { VPNPOOL_GEOIP_TTL=${TTL:-86400} run_with_timeout 60 sh $GS >/dev/null 2>&1; }

reset_state; mock_on
mock_rule "GET $LS/srs/ru.srs" 200 "$GX/ru.srs"
printf '404: Not Found' > "$GX/404.txt"
mock_rule "GET $LS/srs/nosuch.srs" 404 "$GX/404.txt"
mock_rule "GET $LSJ/srs/nosuch.srs" 404 "$GX/404.txt"
mock_rule "GET $LS/srs/html.srs" 200 "$GX/html.txt"
geo_set loyalsoldier '' ru nosuch html
geo_run
begin "geoip/loyalsoldier-srs"
expect_true "control: the .srs was compiled" [ -s "$GX/ru.srs" ]
expect_true "ru.srs in place" cmp -s /tmp/vpnpool/geoip/ru.srs "$GX/ru.srs"
expect_jq "status ru ok" "$(gst ru)" '.ok==true'
expect_jq "status nosuch: not_found (404 at both mirrors)" "$(gst nosuch)" '.==({ok:false, error:"not_found"})'
expect_jq "status html: bad_file (not an .srs)" "$(gst html)" '.==({ok:false, error:"bad_file"})'
expect_true "no file for the refused ones" sh -c '[ ! -e /tmp/vpnpool/geoip/nosuch.srs ] && [ ! -e /tmp/vpnpool/geoip/html.srs ]'
expect_true "fresh mark written (every code got an answer)" [ -s /tmp/vpnpool/geoip/.sig ]
expect_true "flash copy" cmp -s /etc/vpnpool/geoip/ru.srs "$GX/ru.srs"
end
: > /tmp/curlmock/calls.log
geo_run
begin "geoip/fresh-no-download"
expect_eq "no request within the TTL" "$(grep -c . /tmp/curlmock/calls.log)" 0
end

reset_state; mock_on
mock_rule "GET $LSJ/srs/ru.srs" 200 "$GX/ru.srs"   # raw.githubusercontent gives no answer (no rule = 000)
geo_set loyalsoldier '' ru
geo_run
begin "geoip/loyalsoldier-mirror-when-github-gives-no-answer"
expect_jq "ok" "$(gst ru)" '.ok==true'
expect_eq "raw tried first, then jsDelivr" "$(cut -f1 /tmp/curlmock/calls.log | tr '\n' ' ')" "GET $LS/srs/ru.srs GET $LSJ/srs/ru.srs "
end

reset_state; mock_on
mock_rule "GET $V2/text/ru.txt" 200 "$GX/v2ru.txt"
geo_set v2fly '' ru
geo_run
begin "geoip/v2fly-text-made-into-a-source"
expect_jq "ok, 2 networks" "$(gst ru)" '.==({ok:true, n:2})'
expect_eq "ru.json" "$(cidrs /tmp/vpnpool/geoip/ru.json)" '["198.51.100.0/24","2001:db8::/32"]'
expect_true "the text list is not kept" [ ! -e /tmp/vpnpool/geoip/ru.txt ]
end

reset_state; mock_on
mock_rule "GET https://lists.example/geoip.dat" 200 "$TINY"
geo_set url https://lists.example/geoip.dat ru rev
geo_run
begin "geoip/own-geoip-dat"
expect_jq "ru ok" "$(gst ru)" '.==({ok:true, n:4})'
expect_jq "rev: reverse_match" "$(gst rev)" '.==({ok:false, error:"reverse_match"})'
expect_eq "one download for every code" "$(mock_calls 'GET https://lists.example/geoip.dat')" 1
expect_true "the .dat itself is not kept" [ ! -e /tmp/vpnpool/geoip/.geoip.dat ]
end
reset_state; mock_on
geo_set url '' ru
geo_run
begin "geoip/own-geoip-dat-without-address"
expect_jq "no_url" "$(gst ru)" '.==({ok:false, error:"no_url"})'
end
reset_state; mock_on
mock_rule "GET https://lists.example/geoip.dat" 200 "$TINY"
geo_set url https://lists.example/geoip.dat ru
printf 'MemTotal: 65536 kB\nMemAvailable: 1024 kB\n' > "$GX/meminfo"
VPNPOOL_MEMINFO="$GX/meminfo" geo_run
begin "geoip/own-geoip-dat-low-memory"
expect_jq "low_memory, nothing parsed" "$(gst ru)" '.==({ok:false, error:"low_memory"})'
end

# a download that fails keeps the last good copy; no fresh mark, so the next build tries again
reset_state; mock_on
mock_rule "GET $LS/srs/ru.srs" 200 "$GX/ru.srs"
geo_set loyalsoldier '' ru
geo_run
mock_on   # every request: no answer
TTL=0 geo_run
begin "geoip/failed-update-keeps-the-saved-copy"
expect_jq "cached" "$(gst ru)" '.==({ok:true, cached:true})'
expect_true "ru.srs still there" cmp -s /tmp/vpnpool/geoip/ru.srs "$GX/ru.srs"
expect_true "no fresh mark: tried again next time" [ ! -e /tmp/vpnpool/geoip/.sig ]
end
# after a reboot (RAM empty) with no network: the flash copy, no download
rm -rf /tmp/vpnpool/geoip; mock_on
mock_rule "GET $LS/srs/ru.srs" 200 "$GX/ru.srs"; geo_run   # a good run first: a fresh flash mark
rm -rf /tmp/vpnpool/geoip; : > /tmp/curlmock/calls.log
geo_run
begin "geoip/after-reboot-from-flash"
expect_true "ru.srs back from flash" cmp -s /tmp/vpnpool/geoip/ru.srs "$GX/ru.srs"
expect_eq "no request" "$(grep -c . /tmp/curlmock/calls.log)" 0
end
geo_set loyalsoldier ''
geo_run
begin "geoip/no-codes-nothing-kept"
expect_true "RAM and flash emptied" sh -c '[ ! -e /tmp/vpnpool/geoip ] && [ ! -e /etc/vpnpool/geoip ]'
expect_jq "status: no codes" "$(cat /tmp/vpnpool/geoip_status.json)" '.codes=={}'
end

# ---- generator: local rule-sets for the files that are there ----
reset_state
U=9c5b7d60-86ba-4f6f-9f81-29e9afb0c5ce
printf 'vless://%s@203.0.113.10:443?security=tls#N1\n' "$U" > "$GX/n.txt"
ucode /usr/libexec/vpnpool/parser.uc "$GX/n.txt" > "$GX/n.json"
mkdir -p "$GX/gd"; cp "$GX/ru.srs" "$GX/gd/ru.srs"; cp "$GX/l.json" "$GX/gd/de.json"
geo_set loyalsoldier '' ru de missing
uci set vpnpool.main.mode=exclude; uci set vpnpool.main.adaptive_routing=1
uci add_list vpnpool.routing.auto_domain=blocked.example; uci commit vpnpool
_c=$(VPNPOOL_GEOIP_DIR="$GX/gd" ucode /usr/libexec/vpnpool/generator.uc "$GX/n.json" 2>/dev/null)
printf '%s\n' "$_c" > "$GX/cfg.json"
begin "geoip/generator-local-rule-sets"
expect_jq "ru: binary, de: source, missing: left out" "$_c" '[.route.rule_set[] | select(.tag|startswith("geoip-")) | {tag, type, format}] == [{tag:"geoip-ru",type:"local",format:"binary"},{tag:"geoip-de",type:"local",format:"source"}]'
expect_jq "exclude mode: the lists go direct" "$_c" '[.route.rules[] | select(.rule_set == ["geoip-ru","geoip-de"])] == [{rule_set:["geoip-ru","geoip-de"], outbound:"direct"}]'
expect_jq "after the adaptive rule (a site by name wins over an address list)" "$_c" '(.route.rules | map(.rule_set == ["geoip-ru","geoip-de"]) | index(true)) > (.route.rules | map(.domain_suffix == ["blocked.example"]) | index(true))'
expect_true "sing-box check accepts the config" sing-box check -c "$GX/cfg.json"
end
geo_set loyalsoldier ''
_c=$(VPNPOOL_GEOIP_DIR="$GX/gd" ucode /usr/libexec/vpnpool/generator.uc "$GX/n.json" 2>/dev/null)
begin "geoip/generator-no-codes-no-rule"
expect_jq "no geoip rule-set, no rule (files lying around do not count)" "$_c" '([(.route.rule_set // [])[] | select(.tag|startswith("geoip-"))] | length)==0 and ([.route.rules[] | select(.rule_set? and (.rule_set|tostring|contains("geoip")))] | length)==0'
end
