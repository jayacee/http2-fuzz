import socket
import struct

from typing import Generator
import lib.huffman as huffman

class constants:
    # Frame types
    FRAME_DATA          = 0x0
    FRAME_HEADERS       = 0x1
    FRAME_PRIORITY      = 0x2
    FRAME_RST_STREAM    = 0x3
    FRAME_SETTINGS      = 0x4
    FRAME_PUSH_PROMISE  = 0x5
    FRAME_PING          = 0x6
    FRAME_GOAWAY        = 0x7
    FRAME_WINDOW_UPDATE = 0x8
    FRAME_CONTINUATION  = 0x9

    # Flags
    FLAG_END_STREAM  = 0x1
    FLAG_END_HEADERS = 0x4
    FLAG_ACK         = 0x1

    # client connection preface
    CONNECTION_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

    # default settings
    CLIENT_SETTINGS = {
        0x1: 4096,      # HEADER_TABLE_SIZE
        0x3: 100,       # MAX_CONCURRENT_STREAMS
        0x4: 65535,     # INITIAL_WINDOW_SIZE
        0x5: 16384,     # MAX_FRAME_SIZE
    }

def build_frame(frame_type, flags, stream_id, payload):
    # encode a single HTTP/2 frame
    length = len(payload)
    header = struct.pack(">I", length)[1:] # 24-bit length
    header += struct.pack(">BBi", frame_type, flags, stream_id & 0x7FFFFFFF)
    return header + payload


def build_settings_frame(settings):
    payload = b""
    for key, value in settings.items():
        payload += struct.pack(">HI", key, value)
    return build_frame(constants.FRAME_SETTINGS, 0, 0, payload)


def build_settings_ack():
    return build_frame(constants.FRAME_SETTINGS, constants.FLAG_ACK, 0, b"")


def build_window_update(stream_id,increment):
    return build_frame(constants.FRAME_WINDOW_UPDATE, 0, stream_id,
                       struct.pack(">I", increment & 0x7FFFFFFF))


def build_headers_frame(stream_id, header_block, end_stream=True):
    flags = constants.FLAG_END_HEADERS | (constants.FLAG_END_STREAM if end_stream else 0)
    return build_frame(constants.FRAME_HEADERS, flags, stream_id, header_block)

def recv_exact(sock,n):
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Connection closed before expected bytes received")
        buf.extend(chunk)
    return bytes(buf)


def read_frames(sock):
    while True:
        raw = recv_exact(sock, 9)
        length = struct.unpack(">I", b"\x00" + raw[:3])[0]
        frame_type, flags = raw[3], raw[4]
        stream_id = struct.unpack(">I", raw[5:9])[0] & 0x7FFFFFFF
        payload = recv_exact(sock, length) if length else b""
        yield frame_type, flags, stream_id, payload


def http2_get(sock, path,stream_id,ip_address,_hpack_decoder,extra_headers=None):
    try:
        #Build HEADERS frame for our GET request
        req_headers: list[tuple[bytes, bytes]] = [
            (b":method",    b"GET"),
            (b":scheme",    b"http"),
            (b":path",      path.encode()),
            (b":authority", ip_address.encode()),
            (b"user-agent", b"python-http2-fuzz/1.0"),
            (b"accept",     b"*/*"),
        ]
        if extra_headers:
            for k, v in extra_headers.items():
                req_headers.append((k.lower().encode(), v.encode()))

        header_block = huffman.hpack_encode_headers(req_headers)
        sock.sendall(build_headers_frame(stream_id=stream_id, header_block=header_block, end_stream=False))

        #read response frames
        body_parts = []
        resp_headers = {}
        status_code = 0
        server_settings_received = False
        done = False
        continuation_buf: bytes = b""

        for frame_type, flags, stream_id, payload in read_frames(sock):

            if frame_type == constants.FRAME_SETTINGS and not (flags & constants.FLAG_ACK):
                # Server's SETTINGS – ACK it
                sock.sendall(build_settings_ack())
                server_settings_received = True

            elif frame_type == constants.FRAME_SETTINGS and (flags & constants.FLAG_ACK):
                pass  # ACK to our own SETTINGS, nothing to do

            elif frame_type == constants.FRAME_WINDOW_UPDATE:
                pass  # We ignore flow-control updates in this simple client

            elif frame_type == constants.FRAME_PING:
                # Must reply with PING ACK
                sock.sendall(build_frame(constants.FRAME_PING, constants.FLAG_ACK, 0, payload))

            elif frame_type == constants.FRAME_HEADERS:
                # May be followed by CONTINUATION frames
                hblock = payload
                # Strip padding if PADDED flag (0x8) is set
                padded = flags & 0x8
                if padded:
                    pad_length = hblock[0]
                    hblock = hblock[1:len(hblock) - pad_length]
                # Strip priority if PRIORITY flag (0x20) is set
                if flags & 0x20:
                    hblock = hblock[5:]

                if flags & constants.FLAG_END_HEADERS:
                    decoded = _hpack_decoder.decode(hblock)
                    for name, value in decoded:
                        name_s  = name.decode(errors="replace")
                        value_s = value.decode(errors="replace")
                        if name_s == ":status":
                            status_code = int(value_s)
                        else:
                            resp_headers[name_s] = value_s
                else:
                    continuation_buf = hblock

                if (flags & constants.FLAG_END_STREAM) and not body_parts:
                    done = True

            elif frame_type == constants.FRAME_CONTINUATION:
                continuation_buf += payload
                if flags & constants.FLAG_END_HEADERS:
                    decoded = _hpack_decoder.decode(continuation_buf)
                    continuation_buf = b""
                    for name, value in decoded:
                        name_s  = name.decode(errors="replace")
                        value_s = value.decode(errors="replace")
                        if name_s == ":status":
                            status_code = int(value_s)
                        else:
                            resp_headers[name_s] = value_s

            elif frame_type == constants.FRAME_DATA:
                # Strip padding
                padded = flags & 0x8
                data   = payload
                if padded:
                    pad_length = data[0]
                    data = data[1:len(data) - pad_length]
                if data:
                    body_parts.append(data)
                    # Send WINDOW_UPDATE to avoid flow-control stalls
                    inc = len(data)
                    sock.sendall(build_window_update(0, inc))
                    sock.sendall(build_window_update(1, inc))
                if flags & constants.FLAG_END_STREAM:
                    done = True

            elif frame_type == constants.FRAME_RST_STREAM:
                error_code = struct.unpack(">I", payload)[0]
                return (-1,error_code,None)

            elif frame_type == constants.FRAME_GOAWAY:
                last_stream = struct.unpack(">I", payload[:4])[0] & 0x7FFFFFFF
                error_code  = struct.unpack(">I", payload[4:8])[0]
                debug_data  = payload[8:].decode(errors="replace")
                return (-2,error_code,debug_data)

            if done:
                break
    except ConnectionError:
        return (-3,None,None)
    except Exception as e:
        print(e)
        return (-5,None,None)
 
    return status_code, resp_headers, b"".join(body_parts)

