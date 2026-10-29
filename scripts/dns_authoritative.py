#!/usr/bin/env python3
"""Tiny owned UDP A-authority used only by the disposable DNS native proof."""

from __future__ import annotations

import argparse
import socket


def question_end(packet: bytes) -> int:
    offset = 12
    while offset < len(packet):
        length = packet[offset]
        offset += 1
        if length == 0:
            break
        if length > 63 or offset + length > len(packet):
            raise ValueError("malformed DNS question")
        offset += length
    if offset + 4 > len(packet):
        raise ValueError("truncated DNS question")
    return offset + 4


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--answer", default="172.29.0.80")
    args = parser.parse_args()
    answer = socket.inet_aton(args.answer)
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind(("0.0.0.0", 53))
    while True:
        packet, peer = server.recvfrom(4096)
        try:
            end = question_end(packet)
            header = packet[:2] + b"\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00"
            response = (
                header
                + packet[12:end]
                + b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x0e\x10\x00\x04"
                + answer
            )
            server.sendto(response, peer)
        except ValueError:
            continue


if __name__ == "__main__":
    main()
