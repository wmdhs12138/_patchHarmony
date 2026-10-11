#!/usr/bin/env python3
"""V2338A static module ABI preflight. Read-only; NEVER certifies insmod safety."""
import argparse
import csv
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

    # Inspect actual ELF undefined imports; names in kallsyms are not a CRC check.
    undefined = set()
    for sh in sections:
        if sh[1] != 2:  # SHT_SYMTAB
            continue
        if sh[6] >= len(sections) or sh[9] < 24 or sh[5] % sh[9]:
            raise ValueError("Malformed ELF symbol table")
        string_sh = sections[sh[6]]
        symstr = b[string_sh[4]:string_sh[4] + string_sh[5]]
        symtab = b[sh[4]:sh[4] + sh[5]]
        for pos in range(0, len(symtab), sh[9]):
            str_off, info, _other, shndx, _value, _size = struct.unpack_from(
                "<IBBHQQ", symtab, pos)
            if shndx == 0 and str_off and (info & 15) not in (3, 4):
                end = symstr.find(b"\0", str_off)
                if 0 <= str_off < len(symstr) and end > str_off:
                    undefined.add(symstr[str_off:end].decode(
                        "ascii", "replace").split("@", 1)[0])
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
        "module_layout_crc": versions.get("module_layout"),
        "undefined_symbol_count": len(undefined)
    }, versions, undefined

def load_crc_db(path):
    """Accept either observed_crc.tsv or target_crc.tsv from the OEM-only scan."""
    db = {}
    with open(path, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f, delimiter="\t"):
            symbol = row.get("symbol", "").strip()
            status = (row.get("status") or row.get("audit_status") or "OBSERVED").strip()
            raw = (row.get("crc") or row.get("crc_values") or
                   row.get("observed_crc") or "").strip()
            if not symbol or status not in ("OBSERVED", "OK", "UNIQUE") or not raw:
                continue
            try:
                crc = int(raw, 16)
            except ValueError:
                raise ValueError("Ambiguous or invalid reference CRC: " + symbol)
            if symbol in db and db[symbol] != crc:
                raise ValueError("Conflicting OEM reference CRC: " + symbol)
            db[symbol] = crc
    if not db:
        raise ValueError("No valid OEM CRC records in reference")
    return db


def load_inventory(path):
    with open(path, newline="", encoding="utf-8") as f:
        symbols = {row["symbol"] for row in csv.DictReader(f, delimiter="\t")
                   if row.get("symbol")}
    if not symbols:
        raise ValueError("Empty imported symbol inventory")
    return symbols


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("module", type=Path)
    p.add_argument("--json", type=Path)
    p.add_argument("--strict", action="store_true")
    p.add_argument("--crc-db", type=Path, help="OEM-only observed_crc.tsv, read locally")
    p.add_argument("--inventory", type=Path, help="baseline target_crc.tsv, read locally")
    args = p.parse_args()
    try:
        observed, versions, undefined = inspect(args.module)
        crc_db = load_crc_db(args.crc_db) if args.crc_db else None
        baseline = load_inventory(args.inventory) if args.inventory else None
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

    checks = {}
    if baseline is not None:
        checks["import_drift"] = {
            "baseline_count": len(baseline),
            "current_count": len(undefined),
            "new_imports": sorted(undefined - baseline),
            "baseline_imports_no_longer_used": sorted(baseline - undefined),
        }
    if crc_db is not None:
        known = sorted(undefined.intersection(crc_db))
        unknown = sorted(undefined.difference(crc_db))
        mismatch = []
        matched = 0
        without_crc = 0
        for symbol in known:
            got = versions.get(symbol)
            if got is None:
                without_crc += 1
            elif int(got, 16) == crc_db[symbol]:
                matched += 1
            else:
                mismatch.append({"symbol": symbol,
                                 "module": got,
                                 "oem_observed": "0x%08x" % crc_db[symbol]})
        checks["oem_crc"] = {
            "imports_with_oem_observation": len(known),
            "imports_without_oem_observation": unknown,
            "matching_embedded_crc": matched,
            "imports_with_no_embedded_crc": without_crc,
            "crc_mismatches": mismatch,
            "scope": "OEM module observations only, NOT live kernel Module.symvers"
        }
        if mismatch:
            problems.append("embedded symbol CRC differs from OEM observation")

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
        "additional_checks": checks,
        "blockers": problems,
        "limitation": "A metadata match is not proof of full ABI or CFI/BTI/PAC/hook safety. Do not insmod based on this report."
    }
    print("V2338A ABI verdict:", verdict)
    for key, value in observed.items():
        print("%s: %s" % (key, value))
    if baseline is not None:
        drift = checks["import_drift"]
        print("Import inventory: %s expected, %s present, %s new, %s removed" %
              (drift["baseline_count"], drift["current_count"],
               len(drift["new_imports"]),
               len(drift["baseline_imports_no_longer_used"])))
    if crc_db is not None:
        c = checks["oem_crc"]
        print("OEM CRC: %s imported symbols observed, %s unknown, %s matches, %s mismatches, %s no embedded CRC" %
              (c["imports_with_oem_observation"],
               len(c["imports_without_oem_observation"]),
               c["matching_embedded_crc"], len(c["crc_mismatches"]),
               c["imports_with_no_embedded_crc"]))
    for problem in problems:
        print("BLOCKER:", problem)
    print(report["limitation"])
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")
    return 2 if args.strict and problems else 0

if __name__ == "__main__":
    sys.exit(main())
