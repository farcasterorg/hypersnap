#!/usr/bin/env python3
"""Compute QCT_DEPENDENCY_REV, the hash of the vendored QCT3 source tree.

Usage: python3 crates/qct_dependency_rev.py [--list]

The procedure (also in crates/VENDORED.md):

1. Take every regular file under crates/quil-lattice-ct and
   crates/quil-lattice-proof-sys. Skip these build and cache artifacts:
   a path component named `target` or `__pycache__`, and files named
   `Cargo.lock` or `.DS_Store`. A symbolic link is an error.
2. Name each file by its path relative to crates/, with `/` separators,
   for example `quil-lattice-ct/src/lib.rs`.
3. Sort the names by their UTF-8 bytes.
4. Hash with SHA-256:
     "hypersnap/qct-dependency-rev/v1" || 0x00
     then, for each file in sorted order:
       name (UTF-8) || 0x00 || file length (u64, big-endian) || file bytes
5. QCT_DEPENDENCY_REV is the lowercase hex of the digest.

File modes and timestamps are not hashed.
"""
import hashlib
import os
import sys
from pathlib import Path

DOMAIN = b"hypersnap/qct-dependency-rev/v1\x00"
CRATES = ("quil-lattice-ct", "quil-lattice-proof-sys")
SKIP_DIRS = {"target", "__pycache__"}
SKIP_FILES = {"Cargo.lock", ".DS_Store"}


def tree_files(root: Path):
    names = []
    for crate in CRATES:
        base = root / crate
        if not base.is_dir():
            raise SystemExit(f"missing directory: {base}")
        for directory, subdirs, files in os.walk(base):
            for name in subdirs:
                if (Path(directory) / name).is_symlink():
                    raise SystemExit(f"symbolic link: {Path(directory) / name}")
            subdirs[:] = [d for d in subdirs if d not in SKIP_DIRS]
            for name in files:
                path = Path(directory) / name
                if path.is_symlink():
                    raise SystemExit(f"symbolic link: {path}")
                if name in SKIP_FILES:
                    continue
                if not path.is_file():
                    raise SystemExit(f"not a regular file: {path}")
                names.append(path.relative_to(root).as_posix())
    return sorted(names, key=lambda n: n.encode("utf-8"))


def dependency_rev(root: Path, listing=None) -> str:
    digest = hashlib.sha256(DOMAIN)
    for name in tree_files(root):
        data = (root / name).read_bytes()
        digest.update(name.encode("utf-8") + b"\x00")
        digest.update(len(data).to_bytes(8, "big"))
        digest.update(data)
        if listing is not None:
            listing.append((name, len(data), hashlib.sha256(data).hexdigest()))
    return digest.hexdigest()


def main():
    root = Path(__file__).resolve().parent
    listing = [] if "--list" in sys.argv[1:] else None
    rev = dependency_rev(root, listing)
    if listing is not None:
        for name, size, sha in listing:
            print(f"{sha}  {size:>9}  {name}")
        print(f"files: {len(listing)}")
    print(f"QCT_DEPENDENCY_REV = {rev}")


if __name__ == "__main__":
    main()
