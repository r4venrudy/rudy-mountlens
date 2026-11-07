"""Archive a tested native installation with one top-level layout."""
import argparse
from pathlib import Path
import tarfile
import zipfile


def package(stage, target, version):
    dist = Path("dist")
    dist.mkdir(exist_ok=True)
    stem = f"mountlens-{version}-{target}"
    binary = "bin/mountlens.exe" if target.startswith("windows-") else "bin/mountlens"
    entries = [binary, "README.md", "LICENSE", "assets/banner.svg", "docs/RELEASE.md", "examples/before.mountinfo", "examples/after.mountinfo"]
    files = [(name, stage / name) for name in entries]
    if any(not path.is_file() or path.is_symlink() for _, path in files):
        raise ValueError("incomplete native installation")
    if target.startswith("windows-"):
        with zipfile.ZipFile(dist / (stem + ".zip"), "x", compression=zipfile.ZIP_DEFLATED) as out:
            for name, path in files:
                out.write(path, name)
    else:
        with tarfile.open(dist / (stem + ".tar.gz"), "x:gz") as out:
            for name, path in files:
                out.add(path, arcname=name, recursive=False)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("stage", type=Path)
    parser.add_argument("target", choices=("windows-x64", "linux-x64", "macos-arm64"))
    parser.add_argument("version", choices=("0.1.0-preview",))
    args = parser.parse_args()
    package(args.stage, args.target, args.version)
