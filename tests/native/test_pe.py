"""C++ PE parser: equivalence with pefile on real PE files, robustness on malformed input.

Corpus: benign programs compiled with mingw-w64 at test time (tests/corpus_pe/build_corpus.py).
On Windows CI the same comparison runs over system DLLs (test_system_binaries_equivalence).
"""

from __future__ import annotations

import os
import random
import struct
import sys
import time
from pathlib import Path

import pytest

pefile = pytest.importorskip("pefile")

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "corpus_pe"))
import build_corpus  # noqa: E402

FUZZ_ITERATIONS = int(os.environ.get("GK_FUZZ_ITERATIONS", "400"))
# Sanitizer builds run ~15x slower; the time limits detect algorithmic blow-ups, not raw speed.
SLOWDOWN = float(os.environ.get("GK_SLOWDOWN_FACTOR", "1"))


@pytest.fixture(scope="session")
def corpus(tmp_path_factory):
    if not build_corpus.available():
        pytest.skip("mingw-w64 não disponível para gerar o corpus PE")
    return build_corpus.build(tmp_path_factory.mktemp("pecorpus"))


# ----------------------------------------------------------------------------- pefile views

def _escape(raw: bytes) -> str:
    return "".join(chr(b) if 0x20 <= b < 0x7F and b != 0x5C else f"\\x{b:02x}" for b in raw)


def _py_view(pe) -> dict:
    oh, fh = pe.OPTIONAL_HEADER, pe.FILE_HEADER
    view = {
        "machine": fh.Machine, "number_of_sections": fh.NumberOfSections, "timestamp": fh.TimeDateStamp,
        "characteristics": fh.Characteristics, "magic": oh.Magic, "entry_point": oh.AddressOfEntryPoint,
        "image_base": oh.ImageBase, "section_alignment": oh.SectionAlignment, "file_alignment": oh.FileAlignment,
        "size_of_image": oh.SizeOfImage, "size_of_headers": oh.SizeOfHeaders, "checksum": oh.CheckSum,
        "subsystem": oh.Subsystem, "dll_characteristics": oh.DllCharacteristics,
        "number_of_rva_and_sizes": oh.NumberOfRvaAndSizes,
        "is_dll": pe.is_dll(),
    }
    view["sections"] = [
        (_escape(s.Name.split(b"\0")[0]), s.VirtualAddress, s.Misc_VirtualSize, s.PointerToRawData, s.SizeOfRawData,
         s.Characteristics) for s in pe.sections
    ]
    view["entropies"] = [s.get_entropy() for s in pe.sections]
    base = oh.ImageBase
    imports = []
    for attr, delayed in (("DIRECTORY_ENTRY_IMPORT", False), ("DIRECTORY_ENTRY_DELAY_IMPORT", True)):
        for entry in getattr(pe, attr, []):
            for imp in entry.imports:
                imports.append((entry.dll.decode("latin-1"), imp.name.decode("latin-1") if imp.name else "",
                                imp.ordinal if imp.import_by_ordinal else None, imp.address - base, delayed))
    view["imports"] = imports
    exports = []
    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        for sym in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            exports.append((sym.name.decode("latin-1") if sym.name else "", sym.ordinal, sym.address,
                            sym.forwarder.decode("latin-1") if sym.forwarder else ""))
    view["exports"] = sorted(exports)
    resources = []
    if hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
        for t in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            tname = str(t.name) if t.name is not None else pefile.RESOURCE_TYPE.get(t.id, f"#{t.id}")
            for n in getattr(t, "directory", None).entries if hasattr(t, "directory") else []:
                nname = str(n.name) if n.name is not None else f"#{n.id}"
                for lang in n.directory.entries if hasattr(n, "directory") else []:
                    resources.append((tname, nname, lang.id, lang.data.struct.OffsetToData, lang.data.struct.Size))
    view["resources"] = sorted(resources)
    version = {}
    for file_info in getattr(pe, "FileInfo", []) or []:
        for entry in file_info:
            for table in getattr(entry, "StringTable", []):
                for k, v in table.entries.items():
                    version.setdefault(k.decode("utf-8"), v.decode("utf-8"))
    view["version_info"] = version
    tls = 0
    if hasattr(pe, "DIRECTORY_ENTRY_TLS") and pe.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks:
        rva = pe.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks - base
        step = 8 if oh.Magic == 0x20B else 4
        while tls < 64:
            value = pe.get_qword_at_rva(rva + tls * step) if step == 8 else pe.get_dword_at_rva(rva + tls * step)
            if not value:
                break
            tls += 1
    view["tls_callbacks"] = tls
    view["pdb"] = [e.entry.PdbFileName.rstrip(b"\0").decode("latin-1") for e in getattr(pe, "DIRECTORY_ENTRY_DEBUG", [])
                   if e.struct.Type == 2 and getattr(e, "entry", None) is not None and hasattr(e.entry, "PdbFileName")]
    view["overlay_offset"] = pe.get_overlay_data_start_offset()
    return view


def _native_view(r: dict) -> dict:
    view = {k: r[k] for k in ("machine", "number_of_sections", "timestamp", "characteristics", "magic", "entry_point",
                              "image_base", "section_alignment", "file_alignment", "size_of_image", "size_of_headers",
                              "checksum", "subsystem", "dll_characteristics", "number_of_rva_and_sizes", "is_dll")}
    view["sections"] = [(s["name"], s["virtual_address"], s["virtual_size"], s["raw_offset"], s["raw_size"],
                         s["characteristics"]) for s in r["sections"]]
    view["entropies"] = [s["entropy"] for s in r["sections"]]
    view["imports"] = [(i["dll"], i["name"], i["ordinal"], i["iat_rva"], i["delayed"]) for i in r["imports"]]
    view["exports"] = sorted((e["name"], e["ordinal"], e["rva"], e["forwarder"]) for e in r["exports"])
    view["resources"] = sorted((x["type"], x["name"], x["lang"], x["rva"], x["size"]) for x in r["resources"])
    view["version_info"] = r["version_info"]
    view["tls_callbacks"] = r["tls_callbacks"]
    view["pdb"] = [d["pdb_path"] for d in r["debug"] if d["type"] == 2 and d["pdb_path"]]
    view["overlay_offset"] = r["overlay_offset"]
    return view


def _compare(native, data: bytes, label: str) -> dict:
    result = native.parse_pe(data)
    assert result["valid"], (label, result["error"])
    ours, theirs = _native_view(result), _py_view(pefile.PE(data=data))
    for key in theirs:
        if key == "entropies":
            assert ours[key] == pytest.approx(theirs[key], abs=1e-9), (label, key)
        else:
            assert ours[key] == theirs[key], (label, key)
    return result


# ----------------------------------------------------------------------------- equivalence

def test_corpus_equivalence_with_pefile(native, corpus):
    for path in corpus:
        _compare(native, path.read_bytes(), path.name)


def test_corpus_features(native, corpus):
    by_name = {p.name: native.parse_pe_file(p) for p in corpus}
    for arch in ("x64", "x86"):
        dll = by_name[f"exports_{arch}.dll"]
        assert dll["is_dll"] and dll["export_name"] == "gk_exports.dll"
        forwarders = {e["name"]: e["forwarder"] for e in dll["exports"] if e["forwarder"]}
        assert forwarders == {"GetTickProxy": "kernel32.GetTickCount", "CloseProxy": "kernel32.CloseHandle"}
        assert any(e["name"] == "" and e["ordinal"] == 7 for e in dll["exports"])
        res = by_name[f"resources_{arch}.exe"]
        assert res["manifest_execution_level"] == "requireAdministrator"
        assert res["version_info"]["FileDescription"] == "Programa de teste com acentuação"
        embedded = [x for x in res["resources"] if x["type"] == "RT_RCDATA"]
        assert embedded and embedded[0]["magic"] == "pe"
        payload = [x for x in res["resources"] if x["type"] == "BINDATA"][0]
        assert payload["entropy"] > 7.9
        assert res["subsystem"] == 2  # GUI
        basic = by_name[f"basic_{arch}.exe"]
        assert basic["tls_callbacks"] >= 1
        assert any(d["pdb_path"].endswith(f"basic_{arch}.pdb") for d in basic["debug"])
        assert basic["machine_name"] == arch
        assert any(i["dll"].lower() == "user32.dll" and i["name"] == "MessageBoxA" for i in basic["imports"])
        overlay = by_name[f"overlay_{arch}.exe"]
        assert overlay["overlay_magic"] == "zip" and overlay["overlay_size"] == 4 + 4096


def test_address_mapping_equivalence(native, corpus):
    rng = random.Random(5)
    for path in corpus:
        data = path.read_bytes()
        pe = pefile.PE(data=data)
        rvas = [0, 1, pe.OPTIONAL_HEADER.SizeOfHeaders - 1, pe.OPTIONAL_HEADER.SizeOfImage + 10, 0xFFFFFFFF]
        for s in pe.sections:
            rvas += [s.VirtualAddress, s.VirtualAddress + 1, s.VirtualAddress + max(s.Misc_VirtualSize, 1) - 1,
                     s.VirtualAddress + s.SizeOfRawData, s.VirtualAddress + s.Misc_VirtualSize]
        rvas += [rng.randrange(0, pe.OPTIONAL_HEADER.SizeOfImage + 0x2000) for _ in range(200)]
        expected = []
        for rva in rvas:
            try:
                expected.append(pe.get_offset_from_rva(rva))
            except pefile.PEFormatError:
                expected.append(None)
        assert native.pe_rva_to_offset(data, rvas) == expected, path.name
        offsets = [0, 0x3C, len(data) - 1, len(data) + 10] + [rng.randrange(0, len(data)) for _ in range(200)]
        mapped = native.pe_offset_to_rva(data, offsets)
        for off, (_section, rva) in zip(offsets, mapped):
            assert rva == pe.get_rva_from_offset(off), (path.name, off)


# ----------------------------------------------------------------------------- robustness

def _mutate(rng: random.Random, data: bytes) -> bytes:
    buf = bytearray(data)
    choice = rng.random()
    if choice < 0.15:
        return bytes(buf[: rng.randrange(0, len(buf))])
    e_lfanew = struct.unpack_from("<I", buf, 0x3C)[0] if len(buf) >= 0x40 else 0
    hot = min(len(buf), e_lfanew + 0x400) if e_lfanew < len(buf) else min(len(buf), 0x400)
    for _ in range(rng.randint(1, 24)):
        region = hot if rng.random() < 0.7 else len(buf)
        if region <= 0:
            break
        pos = rng.randrange(region)
        kind = rng.random()
        if kind < 0.5:
            buf[pos] = rng.randrange(256)
        elif kind < 0.8 and pos + 4 <= len(buf):
            struct.pack_into("<I", buf, pos, rng.choice([0, 0xFFFFFFFF, 0x7FFFFFFF, 0x80000000, len(buf),
                                                         rng.randrange(1 << 32)]))
        elif pos + 2 <= len(buf):
            struct.pack_into("<H", buf, pos, rng.choice([0, 0xFFFF, 0x8000, rng.randrange(1 << 16)]))
    return bytes(buf)


def test_mutation_fuzzing_never_crashes_or_hangs(native, corpus):
    rng = random.Random(int(os.environ.get("GK_FUZZ_SEED", "20261112")))
    seeds = [p.read_bytes() for p in corpus]
    start = time.monotonic()
    for i in range(FUZZ_ITERATIONS):
        sample = _mutate(rng, rng.choice(seeds))
        t0 = time.monotonic()
        result = native.parse_pe(sample)
        assert time.monotonic() - t0 < 2.0 * SLOWDOWN, f"iteração {i}: análise lenta demais"
        assert isinstance(result["anomalies"], list)
    assert time.monotonic() - start < 120 * SLOWDOWN


def _minimal_pe(**overrides) -> bytearray:
    """Hand-built PE32+ with one section, used to craft malformed structures."""
    buf = bytearray(0x400)
    buf[0:2] = b"MZ"
    struct.pack_into("<I", buf, 0x3C, 0x40)
    buf[0x40:0x44] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", buf, 0x44, 0x8664, overrides.get("sections", 1), 0, 0, 0, 0xF0, 0x0022)
    opt = 0x58
    struct.pack_into("<H", buf, opt, 0x20B)
    struct.pack_into("<I", buf, opt + 16, overrides.get("entry", 0x1000))
    struct.pack_into("<Q", buf, opt + 24, 0x140000000)
    struct.pack_into("<II", buf, opt + 32, 0x1000, 0x200)
    struct.pack_into("<II", buf, opt + 56, 0x3000, 0x200)
    struct.pack_into("<H", buf, opt + 68, 3)
    struct.pack_into("<I", buf, opt + 108, 16)
    for index, (rva, size) in overrides.get("dirs", {}).items():
        struct.pack_into("<II", buf, opt + 112 + 8 * index, rva, size)
    sec = opt + 0xF0
    buf[sec:sec + 8] = b".text\0\0\0"
    struct.pack_into("<IIIIIIHHI", buf, sec + 8, 0x1000, 0x1000, 0x200, 0x200, 0, 0, 0, 0,
                     overrides.get("characteristics", 0x60000020))
    return buf


def test_resource_directory_loop_is_detected(native):
    buf = _minimal_pe(dirs={2: (0x1000, 0x100)})
    # Resource root at file offset 0x200 (RVA 0x1000): one id entry whose subdirectory is the root itself.
    struct.pack_into("<IIHHHH", buf, 0x200, 0, 0, 0, 0, 0, 1)
    struct.pack_into("<II", buf, 0x210, 3, 0x80000000)
    result = native.parse_pe(bytes(buf))
    assert result["valid"] and "resource_loop" in result["anomalies"]


def test_huge_export_counts_are_bounded(native):
    buf = _minimal_pe(dirs={0: (0x1000, 0x28)})
    struct.pack_into("<IIHHIIIIIII", buf, 0x200, 0, 0, 0, 0, 0, 1, 0xFFFFFFFF, 0xFFFFFFFF, 0x1100, 0x1200, 0x1300)
    t0 = time.monotonic()
    result = native.parse_pe(bytes(buf))
    assert time.monotonic() - t0 < 2.0 * SLOWDOWN
    assert "exports_limit_reached" in result["anomalies"]


def test_structural_anomalies(native):
    wx = native.parse_pe(bytes(_minimal_pe(characteristics=0xE0000020)))
    assert "section_write_execute" in wx["anomalies"]
    outside = native.parse_pe(bytes(_minimal_pe(entry=0x9000)))
    assert "entrypoint_outside_sections" in outside["anomalies"]
    many = native.parse_pe(bytes(_minimal_pe(sections=0xFFFF)))
    assert many["valid"] and "sections_over_96" in many["anomalies"]
    truncated = native.parse_pe(bytes(_minimal_pe())[:0x180])
    assert truncated["valid"] and "section_raw_beyond_eof" in truncated["anomalies"]
    assert native.parse_pe(b"MZ" + b"\0" * 100)["valid"] is False
    assert native.parse_pe(b"")["valid"] is False


def test_entropy_matches_reference(native):
    import math
    from collections import Counter

    for data in (b"", b"a" * 100, bytes(range(256)) * 4, random.Random(1).randbytes(5000)):
        counts = Counter(data)
        expected = -sum(c / len(data) * math.log2(c / len(data)) for c in counts.values()) if data else 0.0
        assert native.shannon_entropy(data) == pytest.approx(expected, abs=1e-12)


@pytest.mark.windows_only
@pytest.mark.skipif(sys.platform != "win32", reason="usa DLLs do sistema Windows")
def test_system_binaries_equivalence(native):
    system32 = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32"
    candidates = sorted(p for p in system32.glob("*.dll") if p.stat().st_size < 8 * 1024 * 1024)
    sample = candidates[:: max(1, len(candidates) // 80)][:80]
    compared = 0
    for path in sample:
        try:
            data = path.read_bytes()
        except OSError:
            continue
        _compare(native, data, path.name)
        compared += 1
    assert compared >= 40
