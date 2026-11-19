import os
import stat
from pathlib import Path, PurePosixPath

MAX_FILE = 8 * 1024 * 1024
MAX_TOTAL = 16 * 1024 * 1024
MAX_FILES = 200
MAX_DEPTH = 12
MAX_ENTRIES = 50_000
READ_FLAGS = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)
SKIP = {".git", ".venv", "venv", "node_modules", "__pycache__", ".tox", ".hg", "vendor"}


def supported(name: str) -> bool:
    return name in {"package.json", "package-lock.json", "requirements.txt"} or (
        name.startswith("requirements-") and name.endswith(".txt")
    )


def valid_path(raw: str) -> bool:
    if not raw or len(raw) > 2048 or "\\" in raw or any(ord(c) < 32 for c in raw):
        return False
    parts = raw.split("/")
    return (
        len(parts) <= MAX_DEPTH + 1
        and all(part and part not in {".", ".."} and part not in SKIP for part in parts)
        and supported(parts[-1])
    )


def local_files(root: Path) -> tuple[dict[str, str], list[str]]:
    root = root.resolve()
    if not root.is_dir():
        raise ValueError(f"Directory does not exist: {root}")
    files: dict[str, str] = {}
    warnings = []
    total = 0
    entries_seen = 0
    directories = [root]
    while directories:
        directory = directories.pop()
        depth = len(directory.relative_to(root).parts)
        with os.scandir(directory) as entries:
            for entry in entries:
                entries_seen += 1
                if entries_seen > MAX_ENTRIES:
                    return files, warnings + [f"Stopped discovery after {MAX_ENTRIES:,} directory entries."]
                if entry.is_symlink() or entry.name in SKIP:
                    continue
                if entry.is_dir(follow_symlinks=False) and depth < MAX_DEPTH:
                    directories.append(Path(entry.path))
                if not supported(entry.name) or not entry.is_file(follow_symlinks=False):
                    continue
                relative = Path(entry.path).relative_to(root).as_posix()
                if not valid_path(relative):
                    continue
                if len(files) >= MAX_FILES or total >= MAX_TOTAL:
                    return files, warnings + ["Stopped discovery at the manifest count or size limit."]
                try:
                    fd = os.open(entry.path, READ_FLAGS)
                    with os.fdopen(fd, "rb") as stream:
                        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                            continue
                        limit = min(MAX_FILE, MAX_TOTAL - total)
                        payload = stream.read(limit + 1)
                    if len(payload) > limit:
                        warnings.append(f"{relative}: manifest exceeds the scan size limit.")
                        continue
                    files[relative] = payload.decode("utf-8-sig")
                    total += len(payload)
                except (OSError, UnicodeError):
                    warnings.append(f"{relative}: could not read a UTF-8 manifest.")
    return files, warnings


def upload_files(data: object) -> dict[str, str]:
    if not isinstance(data, dict) or len(data) > MAX_FILES:
        raise ValueError("Send a mapping of up to 200 supported manifest files.")
    total = 0
    files = {}
    for path, content in data.items():
        if not isinstance(path, str) or not valid_path(path) or not isinstance(content, str):
            raise ValueError("Upload contains an unsupported manifest path or content.")
        size = len(content.encode("utf-8"))
        total += size
        if size > MAX_FILE or total > MAX_TOTAL:
            raise ValueError("Manifest upload exceeds the scan size limit.")
        files[PurePosixPath(path).as_posix()] = content.removeprefix("\ufeff")
    return files
