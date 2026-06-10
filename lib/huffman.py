import struct

_STATIC_TABLE = {
    1:  (b":authority",        b""),
    2:  (b":method",           b"GET"),
    3:  (b":method",           b"POST"),
    4:  (b":path",             b"/"),
    5:  (b":path",             b"/index.html"),
    6:  (b":scheme",           b"http"),
    7:  (b":scheme",           b"https"),
    8:  (b":status",           b"200"),
    9:  (b":status",           b"204"),
    10: (b":status",           b"206"),
    11: (b":status",           b"304"),
    12: (b":status",           b"400"),
    13: (b":status",           b"404"),
    14: (b":status",           b"500"),
    15: (b"accept-charset",    b""),
    16: (b"accept-encoding",   b"gzip, deflate"),
    17: (b"accept-language",   b""),
    18: (b"accept-ranges",     b""),
    19: (b"accept",            b""),
    20: (b"access-control-allow-origin", b""),
    21: (b"age",               b""),
    22: (b"allow",             b""),
    23: (b"authorization",     b""),
    24: (b"cache-control",     b""),
    25: (b"content-disposition", b""),
    26: (b"content-encoding",  b""),
    27: (b"content-language",  b""),
    28: (b"content-length",    b""),
    29: (b"content-location",  b""),
    30: (b"content-range",     b""),
    31: (b"content-type",      b""),
    32: (b"cookie",            b""),
    33: (b"date",              b""),
    34: (b"etag",              b""),
    35: (b"expect",            b""),
    36: (b"expires",           b""),
    37: (b"from",              b""),
    38: (b"host",              b""),
    39: (b"if-match",          b""),
    40: (b"if-modified-since", b""),
    41: (b"if-none-match",     b""),
    42: (b"if-range",          b""),
    43: (b"if-unmodified-since", b""),
    44: (b"last-modified",     b""),
    45: (b"link",              b""),
    46: (b"location",          b""),
    47: (b"max-forwards",      b""),
    48: (b"proxy-authenticate", b""),
    49: (b"proxy-authorization", b""),
    50: (b"range",             b""),
    51: (b"referer",           b""),
    52: (b"refresh",           b""),
    53: (b"retry-after",       b""),
    54: (b"server",            b""),
    55: (b"set-cookie",        b""),
    56: (b"strict-transport-security", b""),
    57: (b"transfer-encoding", b""),
    58: (b"user-agent",        b""),
    59: (b"vary",              b""),
    60: (b"via",               b""),
    61: (b"www-authenticate",  b""),
}

_STATIC_BY_PAIR  = {v: k for k, v in _STATIC_TABLE.items()}

_STATIC_BY_NAME  = {}
for _idx, (_n, _v) in _STATIC_TABLE.items():
    _STATIC_BY_NAME.setdefault(_n, _idx)


def _hpack_encode_int(value,prefix_bits):
    #encode an integer
    max_prefix = (1 << prefix_bits) - 1
    if value < max_prefix:
        return bytes([value])
    out = bytearray([max_prefix])
    value -= max_prefix
    while value >= 128:
        out.append((value & 0x7F) | 0x80)
        value >>= 7
    out.append(value)
    return bytes(out)


def _hpack_encode_str(s):
    #encode a string
    length = _hpack_encode_int(len(s), 7)
    # First byte: H=0 (no Huffman) merged with the length integer
    return bytes([length[0] & 0x7F]) + length[1:] + s


def hpack_encode_headers(headers):
    #encode a list of name:value pairs (dict)
    out = bytearray()
    for name, value in headers:
        pair = (name, value)
        if pair in _STATIC_BY_PAIR:
            # Indexed Header Field representation (§6.1)
            idx = _STATIC_BY_PAIR[pair]
            first, *rest = _hpack_encode_int(idx, 7)
            out.append(first | 0x80)
            out.extend(rest)
        elif name in _STATIC_BY_NAME:
            # Literal Header Field with Name Index (§6.2.1)
            idx = _STATIC_BY_NAME[name]
            first, *rest = _hpack_encode_int(idx, 6)
            out.append(first | 0x40)          # 01xxxxxx
            out.extend(rest)
            out.extend(_hpack_encode_str(value))
        else:
            # Literal Header Field with New Name (§6.2.1)
            out.append(0x40)
            out.extend(_hpack_encode_str(name))
            out.extend(_hpack_encode_str(value))
    return bytes(out)

def _hpack_decode_int(data, offset, prefix_bits):
    mask = (1 << prefix_bits) - 1
    value = data[offset] & mask
    offset += 1
    if value < mask:
        return value, offset
    shift = 0
    while True:
        b = data[offset]; offset += 1
        value += (b & 0x7F) << shift
        shift += 7
        if not (b & 0x80):
            break
    return value, offset



#hpack huffman encoding table
_HUFFMAN_TABLE = [
    (0x1ff8,13), (0x7fffd8,23), (0xfffffe2,28), (0xfffffe3,28),
    (0xfffffe4,28), (0xfffffe5,28), (0xfffffe6,28), (0xfffffe7,28),
    (0xfffffe8,28), (0xffffea,24), (0x3ffffffc,30), (0xfffffe9,28),
    (0xfffffea,28), (0x3ffffffd,30), (0xfffffeb,28), (0xfffffec,28),
    (0xfffffed,28), (0xfffffee,28), (0xfffffef,28), (0xffffff0,28),
    (0xffffff1,28), (0xffffff2,28), (0x3ffffffe,30), (0xffffff3,28),
    (0xffffff4,28), (0xffffff5,28), (0xffffff6,28), (0xffffff7,28),
    (0xffffff8,28), (0xffffff9,28), (0xffffffa,28), (0xffffffb,28),
    (0x14,6), (0x3f8,10), (0x3f9,10), (0xffa,12),
    (0x1ff9,13), (0x15,6), (0xf8,8), (0x7fa,11),
    (0x3fa,10), (0x3fb,10), (0xf9,8), (0x7fb,11),
    (0xfa,8), (0x16,6), (0x17,6), (0x18,6),
    (0x0,5), (0x1,5), (0x2,5), (0x19,6),
    (0x1a,6), (0x1b,6), (0x1c,6), (0x1d,6),
    (0x1e,6), (0x1f,6), (0x5c,7), (0xfb,8),
    (0x7ffc,15), (0x20,6), (0xffb,12), (0x3fc,10),
    (0x1ffa,13), (0x21,6), (0x5d,7), (0x5e,7),
    (0x5f,7), (0x60,7), (0x61,7), (0x62,7),
    (0x63,7), (0x64,7), (0x65,7), (0x66,7),
    (0x67,7), (0x68,7), (0x69,7), (0x6a,7),
    (0x6b,7), (0x6c,7), (0x6d,7), (0x6e,7),
    (0x6f,7), (0x70,7), (0x71,7), (0x72,7),
    (0xfc,8), (0x73,7), (0xfd,8), (0x1ffb,13),
    (0x7fff0,19), (0x1ffc,13), (0x3ffc,14), (0x22,6),
    (0x7ffd,15), (0x3,5), (0x23,6), (0x4,5),
    (0x24,6), (0x5,5), (0x25,6), (0x26,6),
    (0x27,6), (0x6,5), (0x74,7), (0x75,7),
    (0x28,6), (0x29,6), (0x2a,6), (0x7,5),
    (0x2b,6), (0x76,7), (0x2c,6), (0x8,5),
    (0x9,5), (0x2d,6), (0x77,7), (0x78,7),
    (0x79,7), (0x7a,7), (0x7b,7), (0x7ffe,15),
    (0x7fc,11), (0x3ffd,14), (0x1ffd,13), (0xffffffc,28),
    (0xfffe6,20), (0x3fffd2,22), (0xfffe7,20), (0xfffe8,20),
    (0x3fffd3,22), (0x3fffd4,22), (0x3fffd5,22), (0x7fffd9,23),
    (0x3fffd6,22), (0x7fffda,23), (0x7fffdb,23), (0x7fffdc,23),
    (0x7fffdd,23), (0x7fffde,23), (0xffffeb,24), (0x7fffdf,23),
    (0xffffec,24), (0xffffed,24), (0x3fffd7,22), (0x7fffe0,23),
    (0xffffee,24), (0x7fffe1,23), (0x7fffe2,23), (0x7fffe3,23),
    (0x7fffe4,23), (0x1fffdc,21), (0x3fffd8,22), (0x7fffe5,23),
    (0x3fffd9,22), (0x7fffe6,23), (0x7fffe7,23), (0xffffef,24),
    (0x3fffda,22), (0x1fffdd,21), (0xfffe9,20), (0x3fffdb,22),
    (0x3fffdc,22), (0x7fffe8,23), (0x7fffe9,23), (0x1fffde,21),
    (0x7fffea,23), (0x3fffdd,22), (0x3fffde,22), (0xfffff0,24),
    (0x1fffdf,21), (0x3fffdf,22), (0x7fffeb,23), (0x7fffec,23),
    (0x1fffe0,21), (0x1fffe1,21), (0x3fffe0,22), (0x1fffe2,21),
    (0x7fffed,23), (0x3fffe1,22), (0x7fffee,23), (0x7fffef,23),
    (0xfffea,20), (0x3fffe2,22), (0x3fffe3,22), (0x3fffe4,22),
    (0x7ffff0,23), (0x3fffe5,22), (0x3fffe6,22), (0x7ffff1,23),
    (0x3ffffe0,26), (0x3ffffe1,26), (0xfffeb,20), (0x7fff1,19),
    (0x3fffe7,22), (0x7ffff2,23), (0x3fffe8,22), (0x1ffffec,25),
    (0x3ffffe2,26), (0x3ffffe3,26), (0x3ffffe4,26), (0x7ffffde,27),
    (0x7ffffdf,27), (0x3ffffe5,26), (0xfffff1,24), (0x1ffffed,25),
    (0x7fff2,19), (0x1fffe3,21), (0x3ffffe6,26), (0x7ffffe0,27),
    (0x7ffffe1,27), (0x3ffffe7,26), (0x7ffffe2,27), (0xfffff2,24),
    (0x1fffe4,21), (0x1fffe5,21), (0x3ffffe8,26), (0x3ffffe9,26),
    (0xffffffd,28), (0x7ffffe3,27), (0x7ffffe4,27), (0x7ffffe5,27),
    (0xfffec,20), (0xfffff3,24), (0xfffed,20), (0x1fffe6,21),
    (0x3fffe9,22), (0x1fffe7,21), (0x1fffe8,21), (0x7ffff3,23),
    (0x3fffea,22), (0x3fffeb,22), (0x1ffffee,25), (0x1ffffef,25),
    (0xfffff4,24), (0xfffff5,24), (0x3ffffea,26), (0x7ffff4,23),
    (0x3ffffeb,26), (0x7ffffe6,27), (0x3ffffec,26), (0x3ffffed,26),
    (0x7ffffe7,27), (0x7ffffe8,27), (0x7ffffe9,27), (0x7ffffea,27),
    (0x7ffffeb,27), (0xffffffe,28), (0x7ffffec,27), (0x7ffffed,27),
    (0x7ffffee,27), (0x7ffffef,27), (0x7fffff0,27), (0x3ffffee,26),
    (0x3fffffff,30),  # 256 = EOS (padding sentinel only, not a real byte)
]

def _build_huffman_decode_table():
    return {(code, nbits): sym for sym, (code, nbits) in enumerate(_HUFFMAN_TABLE)}

_HUFFMAN_DECODE: dict[tuple[int, int], int] | None = None


def huffman_decode(data):
    global _HUFFMAN_DECODE
    if _HUFFMAN_DECODE is None:
        _HUFFMAN_DECODE = _build_huffman_decode_table()

    # Build a bit string, then consume symbols one at a time using a
    # simple longest-match scan (max code length is 30 bits).
    bits = int.from_bytes(data, "big")
    total_bits = len(data) * 8
    pos = 0
    out = bytearray()

    while pos < total_bits:
        remaining = total_bits - pos
        matched = False
        for nbits in range(5, min(31, remaining + 1)):
            shift = total_bits - pos - nbits
            code  = (bits >> shift) & ((1 << nbits) - 1)
            sym   = _HUFFMAN_DECODE.get((code, nbits))
            if sym is not None:
                out.append(sym)
                pos += nbits
                matched = True
                break
        if not matched:
            # Remaining bits are EOS padding — verify they're all 1s
            remaining = total_bits - pos
            if remaining >= 8:
                raise ValueError(f"Huffman decode failed at bit {pos}")
            break  # trailing padding ≤ 7 bits

    return bytes(out)


def _hpack_decode_str(data, offset):
    huffman = bool(data[offset] & 0x80)
    length, offset = _hpack_decode_int(data, offset, 7)
    raw = data[offset:offset + length]
    offset += length
    return (huffman_decode(raw) if huffman else raw), offset


def hpack_decode_headers(data):
    static = list(_STATIC_TABLE.values())   # 0-indexed copy for convenience
    dynamic: list[tuple[bytes, bytes]] = []

    def lookup(idx: int) -> tuple[bytes, bytes]:
        # HPACK indices are 1-based; static table has 61 entries
        if 1 <= idx <= 61:
            return _STATIC_TABLE[idx]
        dyn_idx = idx - 62
        if dyn_idx < len(dynamic):
            return dynamic[dyn_idx]
        raise ValueError(f"HPACK index {idx} out of range")

    headers: list[tuple[bytes, bytes]] = []
    offset = 0
    while offset < len(data):
        b = data[offset]
        if b & 0x80:
            # Indexed Header Field
            idx, offset = _hpack_decode_int(data, offset, 7)
            headers.append(lookup(idx))
        elif b & 0x40:
            #  Literal Header Field with Incremental Indexing
            idx, offset = _hpack_decode_int(data, offset, 6)
            if idx:
                name = lookup(idx)[0]
            else:
                name, offset = _hpack_decode_str(data, offset)
            value, offset = _hpack_decode_str(data, offset)
            entry = (name, value)
            dynamic.insert(0, entry)
            headers.append(entry)
        elif b & 0x20:
            # Dynamic Table Size Update – skip
            _, offset = _hpack_decode_int(data, offset, 5)
        else:
            #  Literal Header Field without Indexing / Never Indexed
            idx, offset = _hpack_decode_int(data, offset, 4)
            if idx:
                name = lookup(idx)[0]
            else:
                name, offset = _hpack_decode_str(data, offset)
            value, offset = _hpack_decode_str(data, offset)
            headers.append((name, value))
    return headers


