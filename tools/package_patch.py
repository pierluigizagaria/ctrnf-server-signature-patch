"""Package the committed shadPS4 patch without requiring game files."""

import json
from pathlib import Path
import xml.etree.ElementTree as ET
import zipfile

ROOT = Path(__file__).resolve().parents[1]
TITLE_ID = "CUSA13795"
APP_VER = "01.21"
XML_NAME = "CrashTeamRacingNitroFueled.xml"
PACKAGE_ROOT = "ctrnf-server-signature-patch"
PACKAGE = ROOT / "dist" / f"{PACKAGE_ROOT}-{TITLE_ID}-{APP_VER}.zip"


def build_package(root=ROOT):
    sources = {
        XML_NAME: root / XML_NAME,
        "files.json": root / "files.json",
        "README.md": root / "docs/INSTALLATION.md",
        "LICENSE": root / "LICENSE",
    }
    # Normalize text line endings so Windows and Linux produce identical ZIPs.
    files = {name: path.read_text(encoding="utf-8").encode("utf-8")
             for name, path in sources.items()}
    patch = ET.fromstring(files[XML_NAME])
    if patch.tag != "Patch" or [node.text for node in patch.findall("TitleID/ID")] != [TITLE_ID]:
        raise ValueError("Patch title ID differs from the supported game")
    metadata = patch.findall("Metadata")
    if len(metadata) != 1 or any(metadata[0].get(key) != value for key, value in {
            "AppVer": APP_VER, "AppElf": "eboot.bin", "isEnabled": "false"}.items()):
        raise ValueError("Patch must target the supported version and be disabled by default")
    lines = metadata[0].findall("PatchList/Line")
    if len(lines) != 1 or lines[0].attrib != {
            "Type": "bytes", "Address": "0x00413ec0", "Value": "909090909090"}:
        raise ValueError("Patch instructions differ from the verified signature patch")
    if json.loads(files["files.json"]) != {XML_NAME: [TITLE_ID]}:
        raise ValueError("Title index does not match the patch")
    if not files["README.md"].strip() or not files["LICENSE"].strip():
        raise ValueError("Installation instructions and license are required")

    package = root / "dist" / PACKAGE.name
    package.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(package, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data in files.items():
            entry = zipfile.ZipInfo(f"{PACKAGE_ROOT}/{name}")
            entry.compress_type = zipfile.ZIP_DEFLATED
            entry.create_system = 3
            entry.external_attr = 0o100644 << 16
            archive.writestr(entry, data)
    with zipfile.ZipFile(package) as archive:
        if archive.testzip() is not None or set(archive.namelist()) != {
                f"{PACKAGE_ROOT}/{name}" for name in files}:
            raise ValueError("Native patch package failed validation")
    return package


if __name__ == "__main__":
    print(build_package())
