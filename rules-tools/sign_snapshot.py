#!/usr/bin/env python3
"""Prepare a signed manifest for a validated rules snapshot."""
import hashlib
import json
import pathlib
import subprocess
import sys

def main():
    snapshot, key, output = map(pathlib.Path, sys.argv[1:])
    data = snapshot.read_bytes()
    bundle = json.loads(data)
    if not isinstance(bundle.get("updatedAt"), int) or bundle["updatedAt"] <= 0:
        raise ValueError("invalid snapshot version")
    if len(data) > 128 * 1024 * 1024:
        raise ValueError("snapshot exceeds client limit")
    digest = hashlib.sha256(data).hexdigest()
    output.mkdir(parents=True, exist_ok=True)
    name = f"rules-{digest}.json"
    (output / name).write_bytes(data)
    manifest = output / "manifest.json"
    manifest.write_text(json.dumps({
        "schema": 1,
        "version": bundle["updatedAt"],
        "file": name,
        "sha256": digest,
        "size": len(data)
    }, sort_keys=True, separators=(",", ":")), encoding="utf-8")
    subprocess.run(["openssl", "pkeyutl", "-sign", "-rawin",
                    "-inkey", str(key), "-in", str(manifest),
                    "-out", str(output / "manifest.sig")], check=True)

if __name__ == "__main__":
    main()
