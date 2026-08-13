#!/usr/bin/env python3
"""
Regenerate the checked-in protobuf bindings under findmy/cloudkit/proto/.

The generated code is committed so that neither a build step nor a protoc install stands
between a clone and a working library. Run this after editing any .proto file.

    uv run scripts/gen_proto.py

It deliberately does not use whatever protoc happens to be on PATH. Generated code carries
a minimum runtime version and refuses to load on anything older, so a newer protoc quietly
raises the library's protobuf floor for every consumer. Pinning the compiler here keeps
that floor a decision rather than a side effect of a developer's Homebrew.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

# Pins the generated code's minimum protobuf runtime, which must stay at or below the
# floor declared in pyproject.toml. grpcio-tools is used rather than a protoc binary
# because it is installable from PyPI at an exact version on every platform.
GRPCIO_TOOLS_VERSION = "1.68.1"

REPO_ROOT = Path(__file__).resolve().parent.parent
PROTO_FILES = [
    "findmy/cloudkit/proto/cloudkit.proto",
    "findmy/cloudkit/proto/cuttlefish.proto",
]


def main() -> int:
    """Regenerate every .proto listed above, in place."""
    cmd = [
        "uvx",
        "--from",
        f"grpcio-tools=={GRPCIO_TOOLS_VERSION}",
        "python",
        "-m",
        "grpc_tools.protoc",
        "--proto_path=.",
        "--python_out=.",
        "--pyi_out=.",
        *PROTO_FILES,
    ]

    print("$", " ".join(cmd))
    result = subprocess.run(cmd, cwd=REPO_ROOT, check=False)
    if result.returncode != 0:
        print("protoc failed", file=sys.stderr)
        return result.returncode

    for proto in PROTO_FILES:
        print("wrote", proto.replace(".proto", "_pb2.py"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
