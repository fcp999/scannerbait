"""Observe unicast UDP/5353 probes forwarded by the edge router."""

import socket
import struct


def describe(packet):
    """Read the DNS header and first question only."""
    if len(packet) < 12:
        return {"kind": "unparsed", "reason": "short_header"}

    _, flags, questions, answers, _, _ = struct.unpack_from("!6H", packet)
    fields = {
        "kind": "response" if flags & 0x8000 else "query",
        "questions": questions,
        "answers": answers,
    }
    if not questions:
        return fields

    # The first question has no earlier domain name to point back to.
    labels = []
    offset = 12
    while offset < len(packet) and offset - 12 < 255:
        size = packet[offset]
        offset += 1
        if size == 0:
            if offset + 4 <= len(packet):
                qtype, qclass = struct.unpack_from("!HH", packet, offset)
                fields.update(qname=".".join(labels) + ".", qtype=qtype,
                              qclass=qclass & 0x7fff, unicast_requested=bool(qclass & 0x8000))
                return fields
            break
        if size > 63 or offset + size > len(packet):
            break
        label = packet[offset:offset + size].decode("ascii", "backslashreplace")
        labels.append(label.replace("\\", "\\\\").replace(".", "\\."))
        offset += size
    return {**fields, "kind": "unparsed", "reason": "invalid_first_question"}


def listen():
    from scannerbait import log_event

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as listener:
        listener.bind(("0.0.0.0", 5353))
        while True:
            packet, (peer, port) = listener.recvfrom(65535)
            log_event("mdns_packet", src_ip=peer, src_port=port,
                      size=len(packet), **describe(packet))


if __name__ == "__main__":
    listen()
