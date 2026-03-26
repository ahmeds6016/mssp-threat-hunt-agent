"""Build a deployment zip with correct Unix-style paths for Azure Functions."""

import os
import sys
import zipfile
from pathlib import Path


def build_zip(staging_dir: str, output_path: str) -> None:
    staging = Path(staging_dir)
    with zipfile.ZipFile(output_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for root, dirs, files in os.walk(staging):
            for f in files:
                full_path = Path(root) / f
                # Use forward slashes for the archive path
                arc_name = full_path.relative_to(staging).as_posix()
                zf.write(full_path, arc_name)
    print(f"Created {output_path} ({os.path.getsize(output_path) / 1024 / 1024:.1f} MB)")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python build_zip.py <staging_dir> <output.zip>")
        sys.exit(1)
    build_zip(sys.argv[1], sys.argv[2])
