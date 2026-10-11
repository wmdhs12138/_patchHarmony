#!/usr/bin/env python3
"""Prepare a strictly PARTIAL modpost CRC reference for a minimal vivo loader probe.

Inputs are from the phone. This does not modify the phone, kernel image,
system partitions, OEM modules or any ELF file. It never claims load safety.
Use the output only with a verified, separately prepared matching kernel tree.
"""
import argparse
import csv
import json
import re
import tarfile
from pathlib import Path

KERNEL = "5.15.197-g4875e12dd776-dirty"
EXPECTED = {
    "module_layout": (0x5EC51E3C, 311),
    "__ubsan_handle_cfi_check_fail_abort": (0xDF7A4C69, 311),
}
REQ_CONFIGS = (
    "CONFIG_MODVERSIONS", "CONFIG_CFI_CLANG",
    "CONFIG_LTO_CLANG_FULL", "CONFIG_VIVO_MODULE_VERMAGIC",
    "CONFIG_MODULE_SIG_PROTECT",
)


def kheader(tar, name):
    path = "./" + name
    member = next((m for m in tar.getmembers() if m.name.lstrip("./") == name), None)
    if not member or not member.isfile():
        raise ValueError("Missing kheaders member: " + path)
    handle = tar.extractfile(member)
    if handle is None:
        raise ValueError("Cannot read kheaders member: " + path)
    return handle.read().decode("utf-8", "replace")


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--kheaders", type=Path, required=True)
    p.add_argument("--crc-db", type=Path, required=True)
    p.add_argument("--out-dir", type=Path, required=True)
    args = p.parse_args()

    with tarfile.open(args.kheaders, "r:xz") as tf:
        release_header = kheader(tf, "include/generated/utsrelease.h")
        config_header = kheader(tf, "include/generated/autoconf.h")
        compile_header = kheader(tf, "include/generated/compile.h")

    release = re.search(r'^\s*#define UTS_RELEASE "([^"]+)"', release_header, re.M)
    if not release or release.group(1) != KERNEL:
        raise ValueError("kheaders UTS_RELEASE does NOT match V2338A")
    for key in REQ_CONFIGS:
        if not re.search(r"^#define\s+" + key + r"\s+1\s*$", config_header, re.M):
            raise ValueError("Running-kernel config not confirmed: " + key)

    if "clang version 14.0.7" not in compile_header:
        raise ValueError("Expected vivo compiler version absent from kheaders")

    observations = {}
    with args.crc_db.open(newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh, delimiter="\t"):
            symbol = row.get("symbol", "").strip()
            if symbol not in EXPECTED:
                continue
            crc = int(row["crc"], 16)
            sources = int(row["module_count"])
            source_path = row.get("sample_source", "")
            if not source_path.startswith("/vendor_dlkm/lib/modules/") or \
                    source_path.count("/") != 4:
                raise ValueError("Wrong OEM module family: " + symbol)
            if symbol in observations:
                raise ValueError("Duplicate symbol row: " + symbol)
            observations[symbol] = (crc, sources)

    for sym, expected in EXPECTED.items():
        if observations.get(sym) != expected:
            raise ValueError("%s CRC/module coverage does not match OEM evidence" % sym)

    args.out_dir.mkdir(parents=True, exist_ok=True)
    lines = []
    for sym, (crc, _) in EXPECTED.items():
        # Both are EXPORT_SYMBOL entries in the Android 5.15 kernel.
        lines.append("0x%08x\t%s\tvmlinux\tEXPORT_SYMBOL\t" % (crc, sym))
    (args.out_dir / "vivo_probe_partial.Module.symvers").write_text(
        "\n".join(lines) + "\n", encoding="ascii"
    )
    report = {
        "kernel": KERNEL,
        "compiler_from_kheaders": "Android clang 14.0.7",
        "module_vermagic_extra": "vivo",
        "crc_evidence": {
            sym: {"crc": "0x%08x" % crc, "observed_oem_modules": n}
            for sym, (crc, n) in EXPECTED.items()
        },
        "scope": "Two observed CRC entries only; NOT a full Module.symvers",
        "validation": "Evidence only. Kernel source/config, compile flags, CFI/BTI, GKI symbol protection, and linker output still require verification.",
        "system_partition_writes": "none"
    }
    (args.out_dir / "manifest.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8"
    )
    print("Verified vivo kheaders and two 311/311-supported OEM CRCs.")
    print("Wrote PARTIAL modpost reference:", args.out_dir / "vivo_probe_partial.Module.symvers")
    print("No .ko was changed; no phone system partition was accessed or modified.")


if __name__ == "__main__":
    main()
