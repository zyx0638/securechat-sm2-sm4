"""Build a source submission bundle, deliberately excluding runtime secrets."""

import hashlib
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main():
    destination = ROOT / "output" / "密码学中级实验提交包.zip"
    files = []
    for pattern in ("*.py", "*.bat", "requirements*.txt", "README.md", ".gitignore"):
        files.extend(ROOT.glob(pattern))
    for folder in ("securechat", "tests", "tools", "docs", "samples"):
        files.extend(path for path in (ROOT / folder).rglob("*")
                     if path.is_file() and "__pycache__" not in path.parts and path.suffix != ".pyc")
    files.extend((ROOT / "output").glob("*.docx"))
    files.extend((ROOT / "output").glob("*.md"))
    files.extend(path for path in (ROOT / "output" / "evidence").rglob("*") if path.is_file())
    with zipfile.ZipFile(destination, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(set(files)):
            archive.write(path, "secure-chat-lab/" + path.relative_to(ROOT).as_posix())
    with zipfile.ZipFile(destination) as archive:
        assert archive.testzip() is None
        names = archive.namelist()
        assert not any("/runtime/" in name or "/.venv/" in name or name.endswith("identity.json") for name in names)
        assert "secure-chat-lab/main.py" in names
    checksum = hashlib.sha256(destination.read_bytes()).hexdigest()
    destination.with_suffix(".zip.sha256").write_text(checksum + "  " + destination.name + "\n", encoding="utf-8")
    print(f"{destination}\n{len(names)} files, {destination.stat().st_size:,} bytes\nSHA256 {checksum}")


if __name__ == "__main__":
    main()
