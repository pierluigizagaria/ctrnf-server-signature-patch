"""Verify the supported CTR:NF executable and build the shadPS4 patch package.

Supports CUSA13795 version 01.21. Writes the XML, title index, verification
report and ZIP without modifying the game files.
"""

import argparse
import hashlib
import json
import struct
from pathlib import Path
import xml.etree.ElementTree as ET

from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from orbis_image import OrbisImage
from package_patch import APP_VER, TITLE_ID, XML_NAME, build_package

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT
EXPECTED_GAME = "e3b7a068b5e7be0f976102aa223a74425e7817c67e26e21416163291750c1b83"
DIST = ROOT / "dist"
AUDIT = DIST / "static-audit.json"
OFFSET = 0x13EC0
XML_BASE = 0x400000
ORIGINAL = bytes.fromhex("0f84fc000000")
REPLACEMENT = bytes.fromhex("909090909090")


def digest(data):
    return hashlib.sha256(data).hexdigest()


def sfo_identity(raw):
    magic, _, keys, values, count = struct.unpack_from("<5I", raw)
    if magic != 0x46535000 or count > 4096:
        raise ValueError("Unsupported param.sfo")
    result = {}
    for index in range(count):
        keyoff, _, size, _, valueoff = struct.unpack_from("<HHIII", raw, 20 + 16 * index)
        key = raw[keys + keyoff:].split(b"\0", 1)[0].decode("utf-8")
        if key in ("TITLE_ID", "APP_VER"):
            result[key] = raw[values + valueoff:values + valueoff + size].rstrip(b"\0").decode("utf-8")
    return result


def decoded(raw, address):
    return [{"address": hex(i.address), "bytes": i.bytes.hex(),
             "instruction": i.mnemonic, "operands": i.op_str}
            for i in Cs(CS_ARCH_X86, CS_MODE_64).disasm(raw, address)]


def prepare(game):
    executable = game / "eboot.bin"
    raw = executable.read_bytes()
    if digest(raw) != EXPECTED_GAME:
        raise ValueError("Refusing an executable outside the pinned supported build")
    identity = sfo_identity((game / "sce_sys/param.sfo").read_bytes())
    if identity != {"APP_VER": APP_VER, "TITLE_ID": TITLE_ID}:
        raise ValueError("Refusing a different game or application version")
    image = OrbisImage(raw)
    window = image.read_vaddr(0x13EB9, 18)
    if window.hex() != "e84204000084c00f84fc000000488d5c2408":
        raise ValueError("Original call/test/rejection branch differs")
    original_flow = decoded(window, 0x13EB9)
    if [(i["instruction"], i["operands"]) for i in original_flow[:3]] != [
            ("call", "0x14300"), ("test", "al, al"), ("je", "0x13fc2")]:
        raise ValueError("Original verifier/result/rejection flow differs")
    if image.read_vaddr(OFFSET, len(ORIGINAL)) != ORIGINAL:
        raise ValueError("Original rejection instruction differs")
    failure = decoded(image.read_vaddr(0x13FC2, 8), 0x13FC2)
    if failure[0]["instruction"] != "mov" or failure[0]["operands"] != "r14d, 0x2bc":
        raise ValueError("Original rejection target differs")
    rsa_call = decoded(image.read_vaddr(0x1446F, 5), 0x1446F)
    if rsa_call[0]["instruction"] != "call" or rsa_call[0]["operands"] != "0x184830":
        raise ValueError("Selected verifier no longer calls the RSA wrapper")

    root = ET.Element("Patch")
    ET.SubElement(ET.SubElement(root, "TitleID"), "ID").text = TITLE_ID
    metadata = ET.SubElement(root, "Metadata", {
        "Title": "Crash Team Racing Nitro-Fueled",
        "Name": "CTR:NF Server Signature Patch",
        "Author": "pierluigizagaria", "PatchVer": "0.1",
        "AppVer": APP_VER, "AppElf": "eboot.bin", "isEnabled": "false",
        "Note": "Bypasses server-response signature rejection. CUSA13795 version 01.21 only.",
    })
    ET.SubElement(ET.SubElement(metadata, "PatchList"), "Line", {
        "Type": "bytes", "Address": f"0x{XML_BASE + OFFSET:08x}",
        "Value": REPLACEMENT.hex(),
    })
    xml = ET.tostring(root, encoding="utf-8", xml_declaration=True) + b"\n"
    parsed = ET.fromstring(xml)
    line = parsed.find("Metadata/PatchList/Line")
    # Reproduce the native loader's fixed-base address conversion.
    if int(line.attrib["Address"], 16) - XML_BASE != OFFSET:
        raise ValueError("XML address does not map to the selected original instruction")
    patch_bytes = bytes.fromhex(line.attrib["Value"])
    if patch_bytes != REPLACEMENT or len(patch_bytes) != len(ORIGINAL):
        raise ValueError("XML replacement length/bytes differ")
    patched = window[:7] + patch_bytes + window[13:]
    patched_flow = decoded(patched, 0x13EB9)
    if [i["instruction"] for i in patched_flow] != ["call", "test"] + ["nop"] * 6 + ["lea"]:
        raise ValueError("Replacement does not preserve the call and fall through at 0x13ec6")
    index = {XML_NAME: [TITLE_ID]}
    report = {
        "game": identity, "game_sha256": EXPECTED_GAME,
        "scope": "Server-response signature rejection branch",
        "static_checks": "passed", "enabled_by_default": False,
        "xml_address": line.attrib["Address"], "image_offset": hex(OFFSET),
        "original_bytes": ORIGINAL.hex(), "replacement_bytes": REPLACEMENT.hex(),
        "original_flow": original_flow, "patched_flow": patched_flow,
        "rsa_call": rsa_call, "failure_target": failure,
        "original_branch_if_result_zero": "0x13fc2",
        "original_branch_if_result_nonzero": "0x13ec6",
        "patched_next_address_for_either_result": "0x13ec6",
        "native_xml_sha256": digest(xml),
        "xml_loader_hash_guard": "The builder checks the executable SHA-256; shadPS4 checks the application version",
        "tls_verification": "unaffected", "backend_identity_admission": "unaffected",
        "lobby_frame_mac_validation": "unaffected",
        "original_game_file_modified": False,
    }
    if digest(executable.read_bytes()) != EXPECTED_GAME:
        raise ValueError("Original input changed during preparation")
    OUTPUT.mkdir(parents=True, exist_ok=True)
    (OUTPUT / XML_NAME).write_bytes(xml)
    (OUTPUT / "files.json").write_text(json.dumps(index, indent=2) + "\n", encoding="utf-8", newline="\n")
    DIST.mkdir(parents=True, exist_ok=True)
    AUDIT.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8", newline="\n")
    package = build_package(OUTPUT)
    return {"xml": str(OUTPUT / XML_NAME), "title_id": TITLE_ID, "app_ver": APP_VER,
            "enabled": False, "static_checks": "passed",
            "original_game_unchanged": True, "package": str(package)}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--game-dir", type=Path, required=True,
                        help="Directory containing eboot.bin and sce_sys/param.sfo")
    args = parser.parse_args()
    print(json.dumps(prepare(args.game_dir)))
