#!/usr/bin/env python3
"""V2338A static module ABI preflight. Read-only; NEVER certifies insmod safety."""
import argparse
import json
import struct
import sys
from pathlib import Path

EXPECTED_VERMAGIC = (
    "5.15.197-g4875e12dd776-dirty SMP preempt "
    "mod_unload modversions vivo aarch64"
)
EXPECTED_MODULE_LAYOUT = 0x5EC51E3C
EXPECTED_MODULE_SIZE = 960

def inspect(path):
    b = Path(path).read_bytes()
    if b[:4] != b"\x7fELF" or b[4] != 2 or b[5] != 1:
        raise ValueError("Expected little-endian ELF64 kernel module")
    if struct.unpack_from("<H", b, 18)[0] != 183:
        raise ValueError("Expected AArch64 ELF (machine 183)")

    shoff = struct.unpack_from("<Q", b, 40)[0]
    entsize, num, stridx = struct.unpack_from("<HHH", b, 58)
    if not shoff or entsize < 64 or not num or stridx >= num:
        raise ValueError("Unsupported ELF section header table")
    sections = [struct.unpack_from("<IIQQQQIIQQ", b, shoff + n * entsize)
                for n in range(num)]
    strsec = sections[stridx]
    strs = b[strsec[4]:strsec[4] + strsec[5]]

    def name(offset):
        if offset >= len(strs):
            return ""
        end = strs.find(b"\x00", offset)
        return strs[offset:end].decode("ascii", "replace") if end >= 0 else ""

    named = {name(s[0]): b[s[4]:s[4] + s[5]] for s in sections}
    if ".modinfo" not in named:
        raise ValueError("Module missing .modinfo")
    modinfo = {}
    for entry in named[".modinfo"].split(b"\x00"):
        if b"=" in entry:
            k, val = entry.split(b"=", 1)
            modinfo[k.decode("utf8", "replace")] = val.decode("utf8", "replace")

    versions = {}
    raw = named.get("__versions", b"")
    if len(raw) % 64:
        raise ValueError("Unexpected __versions record width")
    for off in range(0, len(raw), 64):
        value = struct.unpack_from("<Q", raw, off)[0] & 0xffffffff
        symbol = raw[off+8:off+64].split(b"\x00", 1)[0].decode("ascii", "replace")
        if symbol:
            versions[symbol] = "0x%08x" % value
    return {
        "module_name": modinfo.get("name"),
        "vermagic": modinfo.get("vermagic"),
        "struct_module_bytes": len(named.get(".gnu.linkonce.this_module", b"")),
        "versions_section_bytes": len(raw),
        "versioned_symbols": len(versions),
        "module_layout_crc": versions.get("module_layout")
    }

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("module", type=Path)
    p.add_argument("--json", type=Path)
    p.add_argument("--strict", action="store_true")
    args = p.parse_args()
    try:
        observed = inspect(args.module)
    except (OSError, ValueError, struct.error) as exc:
        print("ERROR: Cannot inspect module:", exc, file=sys.stderr)
        return 1
    problems = []
    if observed["module_name"] != "droid_lkm":
        problems.append("unexpected module name")
    if observed["vermagic"] != EXPECTED_VERMAGIC:
        problems.append("vermagic does not match the loaded vivo OEM module")
    if observed["struct_module_bytes"] != EXPECTED_MODULE_SIZE:
        problems.append("struct module section size differs from vivo BTF")
    if not observed["versioned_symbols"]:
        problems.append("missing per-symbol CRC version records")
    if observed["module_layout_crc"] != "0x%08x" % EXPECTED_MODULE_LAYOUT:
        problems.append("module_layout CRC differs from observed vivo OEM value")

    verdict = "BLOCKED_FOR_DEVICE_LOAD" if problems else "METADATA_ALIGNED_NOT_LOAD_CERTIFIED"
    report = {
        "target": str(args.module),
        "verdict": verdict,
        "observed": observed,
        "reference": {
            "running_kernel_build_id": "0c02d5f32f2141da131f66d6d2b72e4b4553bcd6",
            "loaded_oem_vermagic": EXPECTED_VERMAGIC,
            "observed_oem_module_layout_crc": "0x%08x" % EXPECTED_MODULE_LAYOUT,
            "running_kernel_struct_module_bytes": EXPECTED_MODULE_SIZE
        },
        "blockers": problems,
        "limitation": "A metadata match is not proof of full ABI or CFI/BTI/PAC/hook safety. Do not insmod based on this report."
    }
    print("V2338A ABI verdict:", verdict)
    for key, value in observed.items():
        print("%s: %s" % (key, value))
    for problem in problems:
        print("BLOCKER:", problem)
    print(report["limitation"])
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")
    return 2 if args.strict and problems else 0

if __name__ == "__main__":
    sys.exit(main())
