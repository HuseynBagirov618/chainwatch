import os
import re
import subprocess
from pathlib import Path

from .inputs import MAX_FILE, MAX_FILES, MAX_TOTAL, valid_path

OBJECT_ID = re.compile(rb"[0-9a-f]{40}|[0-9a-f]{64}")


def git(repo: Path, *args: str) -> bytes:
    try:
        result = subprocess.run(
            ["git", "--no-replace-objects", "-C", str(repo), *args],
            capture_output=True, timeout=15, check=True,
            env={**os.environ, "GIT_NO_LAZY_FETCH": "1", "GIT_TERMINAL_PROMPT": "0"},
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        raise ValueError("Could not read the requested Git snapshot. Verify that the commit exists locally.") from None
    return result.stdout


def git_files(repo: Path, ref: str) -> tuple[dict[str, str], list[str]]:
    commit = git(repo, "rev-parse", "--verify", "--end-of-options", f"{ref}^{{commit}}").strip()
    if not OBJECT_ID.fullmatch(commit):
        raise ValueError("Expected a Git commit ID.")
    tree = git(repo, "ls-tree", "-r", "-l", "-z", commit.decode("ascii"))
    files = {}
    warnings = []
    total = 0
    for record in tree.split(b"\0"):
        if not record:
            continue
        info, raw_path = record.split(b"\t", 1)
        mode, kind, object_id, size = info.split()
        if mode not in {b"100644", b"100755"} or kind != b"blob" or not OBJECT_ID.fullmatch(object_id):
            continue
        try:
            path = raw_path.decode("utf-8")
        except UnicodeError:
            continue
        if not valid_path(path):
            continue
        if len(files) >= MAX_FILES or total >= MAX_TOTAL:
            warnings.append("Stopped discovery at the manifest count or size limit.")
            break
        if int(size) > min(MAX_FILE, MAX_TOTAL - total):
            warnings.append(f"{path}: manifest exceeds the scan size limit.")
            continue
        blob = git(repo, "cat-file", "blob", object_id.decode("ascii"))
        try:
            files[path] = blob.decode("utf-8-sig")
        except UnicodeError:
            warnings.append(f"{path}: could not read a UTF-8 manifest.")
            continue
        total += len(blob)
    return files, warnings
