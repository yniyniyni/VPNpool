"""Deterministic geoip.dat for stand/tests/suites/geoip.sh -> fixtures/geoip/tiny.dat

    python -I stand/tests/fixtures/geoip/gen.py stand/tests/fixtures/geoip

The v2ray GeoIPList protobuf (repeated GeoIP {country_code=1, cidr=2 {ip=1, prefix=2},
reverse_match=3}); documentation ranges only. The shapes the parser must survive: IPv4 + IPv6,
a reverse_match entry, an entry without addresses, an entry whose code comes AFTER its
addresses, and an unknown field (resource_hash=4) it has to skip.
"""
import ipaddress, os, sys

def varint(n):
    out = b''
    while True:
        b = n & 0x7f; n >>= 7
        out += bytes([b | (0x80 if n else 0)])
        if not n: return out
def field(num, wt, payload):
    key = varint((num << 3) | wt)
    return key + (varint(len(payload)) + payload if wt == 2 else varint(payload))
def cidr(s):
    n = ipaddress.ip_network(s)
    return field(2, 2, field(1, 2, n.network_address.packed) + field(2, 0, n.prefixlen))
def entry(code, nets, reverse=False, code_last=False, extra=b''):
    body = b''.join(cidr(n) for n in nets)
    c = field(1, 2, code.encode())
    body = (body + c) if code_last else (c + body)
    if reverse: body += field(3, 0, 1)
    return field(1, 2, body + extra)

dat = b''.join([
    entry('AD', ['192.0.2.0/24']),
    entry('RU', ['198.51.100.0/24', '203.0.113.0/25', '2001:db8::/32', '2001:db8:abcd:12::/64'],
          extra=field(4, 2, b'\x01' * 32)),
    entry('REV', ['192.0.2.128/25'], reverse=True),
    entry('EMPTY', []),
    entry('XX', ['203.0.113.128/25'], code_last=True),
])
out = sys.argv[1]
os.makedirs(out, exist_ok=True)
open(os.path.join(out, 'tiny.dat'), 'wb').write(dat)
