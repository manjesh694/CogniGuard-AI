"""
CogniGuard AI - Release Builder & Web Asset Sync Script
Author: CogniGuard Engineering Team
Description: Packages src/extension/ into dist/ and docs/ zip bundles and keeps
             docs/, root index.html, and src/web/ synchronized.
"""

import os
import shutil
import zipfile

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
EXT_VERSION = "1.0.4"


def sync_web_assets() -> None:
    """Sync canonical HTML pages from docs/ to root index.html and src/web/."""
    docs_dir = os.path.join(PROJECT_ROOT, "docs")
    web_dir = os.path.join(PROJECT_ROOT, "src", "web")
    os.makedirs(web_dir, exist_ok=True)

    with open(os.path.join(docs_dir, "index.html"), "r", encoding="utf-8") as f:
        index_html = f.read()

    with open(os.path.join(PROJECT_ROOT, "index.html"), "w", encoding="utf-8") as f:
        f.write(index_html)

    src_web_index = (
        index_html.replace('src="icons/icon48.png"', 'src="../extension/icons/icon48.png"')
        .replace(f'href="cogniguard-ai-v{EXT_VERSION}.zip"', f'href="../../docs/cogniguard-ai-v{EXT_VERSION}.zip"')
    )
    with open(os.path.join(web_dir, "index.html"), "w", encoding="utf-8") as f:
        f.write(src_web_index)

    for page in (
        "dashboard.html",
        "demo_portal.html",
        "mobile_app.html",
        "pitch_deck.html",
        "privacy.html",
        "manifest.webmanifest",
        "sw.js",
    ):
        src_page = os.path.join(docs_dir, page)
        if os.path.exists(src_page):
            shutil.copy2(src_page, os.path.join(web_dir, page))


def package_extension() -> None:
    """Package src/extension/ into dist/ and docs/ release zips."""
    ext_dir = os.path.join(PROJECT_ROOT, "src", "extension")
    dist_dir = os.path.join(PROJECT_ROOT, "dist")
    os.makedirs(dist_dir, exist_ok=True)

    targets = [
        os.path.join(dist_dir, f"cogniguard-ai-v{EXT_VERSION}.zip"),
        os.path.join(PROJECT_ROOT, "docs", f"cogniguard-ai-v{EXT_VERSION}.zip"),
    ]
    for dest in targets:
        with zipfile.ZipFile(dest, "w", zipfile.ZIP_DEFLATED) as z:
            for walk_root, _, files in os.walk(ext_dir):
                for fn in sorted(files):
                    full = os.path.join(walk_root, fn)
                    arc = os.path.relpath(full, ext_dir).replace("\\", "/")
                    z.write(full, arc)


if __name__ == "__main__":
    sync_web_assets()
    package_extension()
    print(f"✅ Synced web assets and packaged CogniGuard AI v{EXT_VERSION} zips.")
