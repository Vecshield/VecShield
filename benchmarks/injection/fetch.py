"""Download the benchmark's third-party sources and verify them.

    python benchmarks/injection/fetch.py            # fetch what is missing, verify all
    python benchmarks/injection/fetch.py --record   # first run: write sources.lock.json

Files land in ``.cache/<source id>/`` (git-ignored), one directory per source.
Nothing downloaded is imported or executed: archives are unpacked with
``tarfile``'s ``data`` filter, which refuses links and paths that leave the
target directory, and every later step only reads text out of them.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import tarfile
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1]))

from benchmarks.injection.sources import SOURCES, WIKI_PAGES, WIKI_STRIDE, Source  # noqa: E402

CACHE = HERE / ".cache"
LOCK = HERE / "sources.lock.json"
_UA = {"User-Agent": "injection-benchmark-fetch"}
_MAX_BYTES = 400 * 1024 * 1024


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def _download(url: str, dest: Path, *, attempts: int = 4) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_suffix(dest.suffix + ".part")
    last: Exception | None = None
    for attempt in range(attempts):
        try:
            request = urllib.request.Request(url, headers=_UA)
            with urllib.request.urlopen(request, timeout=120) as response, tmp.open("wb") as out:
                total = 0
                for block in iter(lambda: response.read(1 << 20), b""):
                    total += len(block)
                    if total > _MAX_BYTES:
                        raise RuntimeError(f"{url}: larger than {_MAX_BYTES} bytes")
                    out.write(block)
            tmp.replace(dest)
            return
        except (urllib.error.URLError, TimeoutError, ConnectionError) as exc:
            last = exc
            # The dataset viewer rate-limits bursts (HTTP 429).
            time.sleep(20 * (attempt + 1) if getattr(exc, "code", None) == 429 else 2 * (attempt + 1))
    raise RuntimeError(f"could not download {url}: {last}")


def _file_url(source: Source, path: str) -> str:
    quoted = urllib.parse.quote(path)
    if source.kind == "hf":
        return f"https://huggingface.co/datasets/{source.repo}/resolve/{source.revision}/{quoted}"
    if source.kind == "github_raw":
        return f"https://raw.githubusercontent.com/{source.repo}/{source.revision}/{quoted}"
    raise ValueError(source.kind)


def _fetch_files(source: Source, lock: dict, record: bool) -> list[str]:
    problems = []
    for path in source.files:
        dest = CACHE / source.id / path
        if not dest.exists():
            print(f"  get {source.id}/{path}")
            _download(_file_url(source, path), dest)
        digest = sha256_file(dest)
        key = f"{source.id}/{path}"
        if record and key not in lock:
            lock[key] = {"sha256": digest, "bytes": dest.stat().st_size}
        elif lock.get(key, {}).get("sha256") != digest:
            problems.append(f"{key}: sha256 {digest} does not match the lock file")
    return problems


def _fetch_tarball(source: Source, lock: dict, record: bool) -> list[str]:
    root = CACHE / source.id
    marker = root / ".extracted"
    if not marker.exists():
        archive = CACHE / "_archives" / f"{source.id}.tar.gz"
        if not archive.exists():
            print(f"  get {source.repo}@{source.revision[:12]} (tarball)")
            _download(f"https://codeload.github.com/{source.repo}/tar.gz/{source.revision}",
                      archive)
        tree = root / "tree"
        tree.mkdir(parents=True, exist_ok=True)
        with tarfile.open(archive) as tar:
            members = [m for m in tar.getmembers()
                       if m.isfile() and m.name.lower().endswith(_TEXT_SUFFIXES)
                       and m.size <= 2_000_000]
            tar.extractall(tree, members=members, filter="data")
        marker.write_text(source.revision + "\n")
    key = f"{source.id}/@commit"
    if record and key not in lock:
        lock[key] = {"commit": source.revision}
    elif lock.get(key, {}).get("commit") != marker.read_text().strip():
        return [f"{source.id}: extracted commit does not match the lock file"]
    return []


_TEXT_SUFFIXES = (".md", ".mdx", ".mdc", ".txt", ".rst", ".cursorrules")


def _fetch_wikipedia(source: Source, lock: dict, record: bool) -> list[str]:
    problems = []
    for lang, pages in WIKI_PAGES.items():
        for page in range(pages):
            offset = page * WIKI_STRIDE
            dest = CACHE / source.id / f"{lang}-{offset}.json"
            if not dest.exists():
                print(f"  get wikipedia {lang} offset {offset}")
                query = urllib.parse.urlencode({
                    "dataset": source.repo, "config": f"{source.revision}.{lang}",
                    "split": "train", "offset": offset, "length": 100})
                _download(f"https://datasets-server.huggingface.co/rows?{query}", dest)
                time.sleep(2.0)
            # The viewer's JSON envelope is not byte-stable; hash the article
            # ids and text, which are.
            rows = json.loads(dest.read_text(encoding="utf-8"))["rows"]
            digest = hashlib.sha256()
            for row in rows:
                digest.update(str(row["row"]["id"]).encode())
                digest.update(row["row"]["text"].encode("utf-8"))
            key = f"{source.id}/{lang}-{offset}"
            if record and key not in lock:
                lock[key] = {"content_sha256": digest.hexdigest(), "rows": len(rows)}
            elif lock.get(key, {}).get("content_sha256") != digest.hexdigest():
                problems.append(f"{key}: content does not match the lock file")
    return problems


def fetch_all(*, record: bool = False, only: set[str] | None = None) -> list[str]:
    lock = json.loads(LOCK.read_text()) if LOCK.exists() else {}
    problems: list[str] = []
    for source in SOURCES:
        if only and source.id not in only:
            continue
        print(f"{source.id}  ({source.licence}, {source.split})")
        if source.kind in ("hf", "github_raw"):
            problems += _fetch_files(source, lock, record)
        elif source.kind == "github_tarball":
            problems += _fetch_tarball(source, lock, record)
        elif source.kind == "hf_rows":
            problems += _fetch_wikipedia(source, lock, record)
        if record:
            LOCK.write_text(json.dumps(lock, indent=1, sort_keys=True) + "\n")
    return problems


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--record", action="store_true",
                        help="record hashes of files not yet in sources.lock.json")
    parser.add_argument("--only", nargs="*", help="source ids to fetch")
    args = parser.parse_args()
    problems = fetch_all(record=args.record, only=set(args.only) if args.only else None)
    for problem in problems:
        print("MISMATCH", problem)
    print("verified" if not problems else f"{len(problems)} problem(s)")
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
