#!/usr/bin/ucode
// vpnpool: GeoIP lists -> sing-box rule-set sources ({"version":2,"rules":[{"ip_cidr":[...]}]}),
// the form generator.uc gives sing-box as a LOCAL rule-set (format "source").
//
//   ucode geoip.uc text <in.txt> <out.json>
//       a CIDR list, one per line (v2fly/geoip and Loyalsoldier/geoip "text/<code>.txt"). Lines
//       that are not an IPv4/IPv6 address or CIDR are skipped (comments, blank lines).
//       stdout: {"ok":true,"n":<cidrs>} | {"ok":false,"error":"empty"|"read_failed"|"write_failed"}
//   ucode geoip.uc dat <geoip.dat> <outdir> <code>...
//       a v2ray geoip.dat (protobuf GeoIPList: repeated GeoIP {country_code=1, cidr=2 {ip=1,
//       prefix=2}, reverse_match=3}) -> <outdir>/<code>.json for every code asked for. Only the
//       entries asked for are decoded; every other entry is skipped by its length, so a 20 MB
//       file costs one read and a few hundred jumps. Codes match case-insensitively (the file
//       has "RU", the user writes "ru").
//       stdout: {"codes":{"<code>":{"ok":true,"n":<cidrs>} | {"ok":false,"error":"not_found"|
//                "reverse_match"|"empty"|"write_failed"}}} | {"ok":false,"error":"read_failed"|"bad_file"}
'use strict';

import { readfile, writefile } from 'fs';

function out(v) { printf('%.J\n', v); }

function ruleset(cidrs) {
	return sprintf('%J\n', { version: 2, rules: [ { ip_cidr: cidrs } ] });
}

// an address or CIDR as a list writes it -> the CIDR, or null
function cidr_of(s) {
	s = trim(s);
	let m = match(s, /^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})(\/([0-9]{1,2}))?$/);
	if (m) {
		for (let i = 1; i <= 4; i++) if (int(m[i]) > 255) return null;
		if (m[6] != null && int(m[6]) > 32) return null;
		return (m[6] != null) ? s : s + '/32';
	}
	m = match(s, /^([0-9A-Fa-f:.]+)(\/([0-9]{1,3}))?$/);
	if (m && index(m[1], ':') >= 0 && length(m[1]) >= 2) {
		if (m[3] != null && int(m[3]) > 128) return null;
		return (m[3] != null) ? s : s + '/128';
	}
	return null;
}

function from_text(inp, dst) {
	let raw = readfile(inp);
	if (raw == null) return out({ ok: false, error: 'read_failed' });
	let cidrs = [];
	for (let l in split(raw, /\r?\n/)) {
		let c = cidr_of(l);
		if (c) push(cidrs, c);
	}
	if (!length(cidrs)) return out({ ok: false, error: 'empty' });
	if (!writefile(dst, ruleset(cidrs))) return out({ ok: false, error: 'write_failed' });
	out({ ok: true, n: length(cidrs) });
}

// ---- protobuf, the few bits geoip.dat needs ----
let B = '', P = 0;
function varint() {
	let v = 0, shift = 0;
	while (P < length(B)) {
		let b = ord(B, P++);
		v += (b & 0x7f) * (1 << shift);   // * not |: a length past 31 bits must not turn negative
		if (b < 0x80) return v;
		shift += 7;
		if (shift > 49) return null;
	}
	return null;
}
// skip one field of wire type wt -> false if the file is broken
function skip(wt) {
	if (wt == 0) return varint() != null;
	if (wt == 2) { let n = varint(); if (n == null || P + n > length(B)) return false; P += n; return true; }
	if (wt == 1) { P += 8; return P <= length(B); }
	if (wt == 5) { P += 4; return P <= length(B); }
	return false;
}
function ip_text(bytes) {
	let n = length(bytes);
	if (n == 4) return sprintf('%d.%d.%d.%d', ord(bytes, 0), ord(bytes, 1), ord(bytes, 2), ord(bytes, 3));
	if (n == 16) {
		let g = [];
		for (let i = 0; i < 16; i += 2) push(g, sprintf('%x', ord(bytes, i) * 256 + ord(bytes, i + 1)));
		return join(':', g);
	}
	return null;
}
// one CIDR message in B[P, end) -> "ip/prefix" or null
function cidr_msg(end) {
	let ip = null, prefix = null;
	while (P < end) {
		let tag = varint();
		if (tag == null) return null;
		let f = tag >> 3, wt = tag & 7;
		if (f == 1 && wt == 2) {
			let n = varint();
			if (n == null || P + n > end) return null;
			ip = substr(B, P, n); P += n;
		} else if (f == 2 && wt == 0) prefix = varint();
		else if (!skip(wt)) return null;
	}
	let t = (ip != null) ? ip_text(ip) : null;
	if (t == null || prefix == null || prefix > ((length(ip) == 4) ? 32 : 128)) return null;
	return t + '/' + prefix;
}

function from_dat(inp, dir, codes) {
	B = readfile(inp);
	if (B == null) return out({ ok: false, error: 'read_failed' });
	let want = {}, res = {}, found = {};
	for (let c in codes) { want[lc(c)] = true; res[c] = { ok: false, error: 'not_found' }; }
	P = 0;
	let len = length(B), entries = 0;
	while (P < len) {
		let tag = varint();
		if (tag == null) return out({ ok: false, error: 'bad_file' });
		if (tag != 0x0a) { if (!skip(tag & 7)) return out({ ok: false, error: 'bad_file' }); continue; }
		let n = varint();
		if (n == null || P + n > len) return out({ ok: false, error: 'bad_file' });
		let end = P + n;
		entries++;
		// the code (field 1) comes first from every geoip.dat builder; an entry that has addresses
		// before it is still read: their places are kept until the code says whether it is wanted
		let code = null, cidrs = null, reverse = false, early = [];
		while (P < end) {
			let t = varint();
			if (t == null) return out({ ok: false, error: 'bad_file' });
			let f = t >> 3, wt = t & 7;
			if (f == 1 && wt == 2) {
				let k = varint();
				if (k == null || P + k > end) return out({ ok: false, error: 'bad_file' });
				code = lc(substr(B, P, k)); P += k;
				if (!want[code] || found[code]) break;   // not asked for: jump over the whole entry
				cidrs = [];
				let here = P;
				for (let e in early) { P = e[0]; let c = cidr_msg(e[0] + e[1]); if (c) push(cidrs, c); }
				P = here;
			} else if (f == 2 && wt == 2) {
				let k = varint();
				if (k == null || P + k > end) return out({ ok: false, error: 'bad_file' });
				let s = P;
				if (cidrs != null) { let c = cidr_msg(s + k); if (c) push(cidrs, c); }
				else if (code == null) push(early, [ s, k ]);
				P = s + k;   // the next field, wherever cidr_msg stopped
			} else if (f == 3 && wt == 0) {
				reverse = (varint() ?? 0) != 0;
			} else if (!skip(wt)) return out({ ok: false, error: 'bad_file' });
		}
		P = end;
		if (cidrs == null) continue;
		found[code] = true;
		for (let c in codes) {
			if (lc(c) != code) continue;
			if (reverse) res[c] = { ok: false, error: 'reverse_match' };
			else if (!length(cidrs)) res[c] = { ok: false, error: 'empty' };
			else if (!writefile(dir + '/' + c + '.json', ruleset(cidrs))) res[c] = { ok: false, error: 'write_failed' };
			else res[c] = { ok: true, n: length(cidrs) };
		}
	}
	if (!entries) return out({ ok: false, error: 'bad_file' });
	out({ codes: res });
}

let mode = ARGV[0];
if (mode == 'text' && length(ARGV) == 3) from_text(ARGV[1], ARGV[2]);
else if (mode == 'dat' && length(ARGV) >= 4) from_dat(ARGV[1], ARGV[2], slice(ARGV, 3));
else { warn('usage: geoip.uc text <in.txt> <out.json> | dat <geoip.dat> <outdir> <code>...\n'); exit(2); }
