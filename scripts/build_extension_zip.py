"""Package extension/ into inbox-shield.zip for the Chrome Web Store.

Use this instead of right-clicking the folder: key.pem is the private signing key
and must never ship (anyone holding it can forge updates signed as you). Chrome
also wants manifest.json at the archive ROOT, not nested inside a wrapper folder.

    python scripts/build_extension_zip.py
"""

import io
import json
import os
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "extension")
OUT = os.path.join(ROOT, "inbox-shield.zip")

# Never ship: signing key, its recorded public half, dev notes, OS/editor cruft.
EXCLUDE_NAMES = {"key.pem", ".manifest_key.txt", "README.md", "Thumbs.db", ".DS_Store"}
EXCLUDE_DIRS = {"__pycache__", ".git"}

# Store-enforced manifest limits, checked here so a bad zip never reaches upload.
LIMITS = {"name": 75, "description": 132}


def collect():
    for dirpath, dirs, files in os.walk(SRC):
        dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS]
        for f in sorted(files):
            if f in EXCLUDE_NAMES or f.endswith((".pem", ".crx", ".zip")):
                continue
            full = os.path.join(dirpath, f)
            # Forward slashes: the zip spec requires them, Windows separators break Chrome.
            yield full, os.path.relpath(full, SRC).replace(os.sep, "/")


def preflight():
    with io.open(os.path.join(SRC, "manifest.json"), encoding="utf-8") as fh:
        m = json.load(fh)
    problems = []
    for field, cap in LIMITS.items():
        if len(m.get(field, "")) > cap:
            problems.append("%s is %d chars (limit %d)" % (field, len(m[field]), cap))
    for size in ("16", "48", "128"):
        icon = m.get("icons", {}).get(size)
        if not icon or not os.path.exists(os.path.join(SRC, icon)):
            problems.append("missing icon for size %s" % size)
    return m, problems


def main():
    manifest, problems = preflight()
    if problems:
        print("BLOCKED — fix these first:")
        for p in problems:
            print("  -", p)
        raise SystemExit(1)

    # Ship the manifest without the dev-only ID pin: the Web Store assigns the
    # published extension ID itself. The source manifest keeps "key" so that
    # reloading unpacked updates the existing entry instead of adding a second.
    shipped = {k: v for k, v in manifest.items()
               if k != "key" and not k.startswith("_comment")}

    files = list(collect())
    with zipfile.ZipFile(OUT, "w", zipfile.ZIP_DEFLATED) as z:
        for full, arc in files:
            if arc == "manifest.json":
                z.writestr(arc, json.dumps(shipped, indent=2, ensure_ascii=False))
            else:
                z.write(full, arc)

    print("%s v%s" % (manifest["name"], manifest["version"]))
    print("wrote %s (%d files, %d bytes)" % (OUT, len(files), os.path.getsize(OUT)))
    for _, arc in files:
        print("  ", arc)


if __name__ == "__main__":
    main()
