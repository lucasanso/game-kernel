"""Content-based file type identification (magic bytes first, extension second)."""

from __future__ import annotations

import struct
from dataclasses import dataclass

HEADER_SIZE = 4096
ISO_PROBE_OFFSET = 0x8001

# Groups used by scan filters / prioritisation.
EXECUTABLE_TYPES = {"pe_exe", "pe_dll", "pe_sys", "pe_dotnet_exe", "pe_dotnet_dll", "elf", "macho", "msdos"}
SCRIPT_TYPES = {"bat", "ps1", "vbs", "js", "hta", "wsf", "reg", "psm1", "py", "sh", "ahk", "au3", "inf"}
ARCHIVE_TYPES = {"zip", "jar", "apk", "7z", "rar", "gzip", "bzip2", "xz", "tar", "cab", "iso", "msi", "ole", "zstd"}
SHORTCUT_TYPES = {"lnk", "url"}

SCRIPT_EXTENSIONS = {
    ".bat": "bat", ".cmd": "bat", ".ps1": "ps1", ".psm1": "ps1", ".psd1": "ps1", ".vbs": "vbs", ".vbe": "vbs",
    ".js": "js", ".jse": "js", ".wsf": "wsf", ".wsh": "wsf", ".hta": "hta", ".reg": "reg", ".py": "py",
    ".pyw": "py", ".sh": "sh", ".ahk": "ahk", ".au3": "au3", ".inf": "inf",
}

EXECUTABLE_EXTENSIONS = {
    ".exe", ".dll", ".sys", ".scr", ".com", ".cpl", ".ocx", ".drv", ".efi", ".asi", ".xll", ".pyd", ".mui", ".ax",
    ".node", ".bin", ".dat", ".tmp",
}
EXECUTABLE_RUNNABLE_EXTENSIONS = {".exe", ".dll", ".sys", ".scr", ".com", ".cpl", ".ocx", ".drv", ".efi", ".asi",
                                  ".xll", ".pyd", ".ax", ".node", ".mui"}

ARCHIVE_EXTENSIONS = {
    ".zip": "zip", ".jar": "jar", ".apk": "zip", ".7z": "7z", ".rar": "rar", ".gz": "gzip", ".tgz": "gzip",
    ".bz2": "bzip2", ".xz": "xz", ".tar": "tar", ".cab": "cab", ".iso": "iso", ".msi": "msi", ".zst": "zstd",
}

# Large data containers commonly found in games; in quick mode they only get a header sniff.
GAME_DATA_EXTENSIONS = {
    ".pak", ".pck", ".bik", ".bk2", ".usm", ".wem", ".bnk", ".fsb", ".ogg", ".wav", ".mp3", ".mp4", ".webm",
    ".avi", ".dds", ".png", ".jpg", ".jpeg", ".tga", ".ktx", ".utoc", ".ucas", ".forge", ".vpk", ".arc", ".big",
    ".assets", ".resource", ".ress", ".resS", ".bundle", ".pkg", ".cpk", ".obb", ".gcf", ".rpf", ".wad", ".bsa",
    ".ba2", ".esm", ".esp", ".uasset", ".umap", ".ttf", ".otf", ".fnt", ".srt", ".txt", ".xml", ".json", ".ini",
    ".cfg", ".log", ".lua", ".csv", ".html", ".css", ".svg", ".mo", ".po", ".shader", ".hlsl", ".spv", ".cache",
    ".sav", ".save", ".dmp", ".pdb", ".bmp", ".ico",
}


@dataclass
class TypeInfo:
    kind: str                 # e.g. pe_exe, zip, bat, text, data
    description: str
    group: str                # executable | script | archive | shortcut | document | data | text
    disguised: bool = False   # content type contradicts a benign-looking extension


def _pe_kind(header: bytes) -> tuple[str, str] | None:
    if len(header) < 0x40 or header[:2] != b"MZ":
        return None
    e_lfanew = struct.unpack_from("<I", header, 0x3C)[0]
    if e_lfanew <= 0 or e_lfanew + 24 > len(header):
        # PE header beyond the probe window (rare, but legal) — treat as DOS/unknown PE.
        return ("msdos", "Executável MZ (cabeçalho PE fora da janela de leitura)")
    if header[e_lfanew:e_lfanew + 4] != b"PE\0\0":
        return ("msdos", "Executável MS-DOS (MZ sem cabeçalho PE)")
    characteristics = struct.unpack_from("<H", header, e_lfanew + 22)[0]
    opt = e_lfanew + 24
    is_dll = bool(characteristics & 0x2000)
    subsystem = None
    dotnet = False
    if opt + 2 <= len(header):
        magic = struct.unpack_from("<H", header, opt)[0]
        if magic in (0x10B, 0x20B):
            sub_off = opt + 68
            if sub_off + 2 <= len(header):
                subsystem = struct.unpack_from("<H", header, sub_off)[0]
            dd_base = opt + (96 if magic == 0x10B else 112)
            clr = dd_base + 14 * 8
            if clr + 8 <= len(header):
                dotnet = struct.unpack_from("<I", header, clr)[0] != 0
    if subsystem == 1:  # IMAGE_SUBSYSTEM_NATIVE → driver
        return ("pe_sys", "Driver do Windows (PE nativo)")
    if dotnet:
        return ("pe_dotnet_dll", "Biblioteca .NET") if is_dll else ("pe_dotnet_exe", "Executável .NET")
    return ("pe_dll", "Biblioteca PE (DLL)") if is_dll else ("pe_exe", "Executável PE")


def identify(header: bytes, extension: str, iso_probe: bytes = b"") -> TypeInfo:
    """Identify a file from its first bytes. ``extension`` is lower-case with a dot."""
    ext = extension.lower()
    pe = _pe_kind(header)
    if pe:
        kind, desc = pe
        disguised = ext not in EXECUTABLE_EXTENSIONS and ext not in (".msstyles", ".tlb", ".winmd", ".acm")
        return TypeInfo(kind, desc, "executable", disguised)
    h = header
    if h.startswith(b"\x7fELF"):
        return TypeInfo("elf", "Executável ELF (Linux)", "executable", ext in GAME_DATA_EXTENSIONS)
    if h[:4] in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xca\xfe\xba\xbe") and ext != ".class":
        return TypeInfo("macho", "Executável Mach-O", "executable")
    if h.startswith(b"PK\x03\x04") or h.startswith(b"PK\x05\x06"):
        if ext == ".jar" or b"META-INF/" in h[:512]:
            return TypeInfo("jar", "Arquivo Java (JAR)", "archive")
        return TypeInfo("zip", "Arquivo ZIP", "archive")
    if h.startswith(b"Rar!\x1a\x07"):
        return TypeInfo("rar", "Arquivo RAR", "archive")
    if h.startswith(b"7z\xbc\xaf\x27\x1c"):
        return TypeInfo("7z", "Arquivo 7-Zip", "archive")
    if h.startswith(b"\x1f\x8b"):
        return TypeInfo("gzip", "Arquivo GZIP", "archive")
    if h.startswith(b"BZh"):
        return TypeInfo("bzip2", "Arquivo BZIP2", "archive")
    if h.startswith(b"\xfd7zXZ\x00"):
        return TypeInfo("xz", "Arquivo XZ", "archive")
    if h.startswith(b"\x28\xb5\x2f\xfd"):
        return TypeInfo("zstd", "Arquivo Zstandard", "archive")
    if h.startswith(b"MSCF"):
        return TypeInfo("cab", "Arquivo CAB", "archive")
    if h.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        if ext in (".msi", ".msp", ".msm"):
            return TypeInfo("msi", "Pacote Windows Installer (MSI)", "archive")
        return TypeInfo("ole", "Documento OLE (Office/MSI)", "document")
    if len(h) > 262 and h[257:262] == b"ustar":
        return TypeInfo("tar", "Arquivo TAR", "archive")
    if iso_probe.startswith(b"CD001"):
        return TypeInfo("iso", "Imagem de disco ISO 9660", "archive")
    if h.startswith(b"L\x00\x00\x00\x01\x14\x02\x00"):
        return TypeInfo("lnk", "Atalho do Windows (LNK)", "shortcut")
    if h.startswith(b"%PDF"):
        return TypeInfo("pdf", "Documento PDF", "document")
    if h.startswith(b"\xca\xfe\xba\xbe") and ext == ".class":
        return TypeInfo("java_class", "Classe Java", "executable")
    if h.startswith(b"MEI\x0c\x0b\x0a\x0b\x0e"):
        return TypeInfo("pyinstaller_archive", "Arquivo PyInstaller", "archive")
    if ext in SCRIPT_EXTENSIONS:
        return TypeInfo(SCRIPT_EXTENSIONS[ext], f"Script ({ext})", "script")
    if ext == ".url" and b"[InternetShortcut]" in h[:256]:
        return TypeInfo("url", "Atalho de Internet (.url)", "shortcut")
    if ext in ARCHIVE_EXTENSIONS:
        return TypeInfo("corrupt_archive", f"Arquivo {ext} com cabeçalho inválido", "archive")
    if _looks_like_text(h):
        stripped = h.lstrip(b"\xef\xbb\xbf").lstrip().lower()
        if stripped.startswith(b"@echo") or b"\n@echo off" in h.lower():
            return TypeInfo("bat", "Script batch (sem extensão de script)", "script", ext not in (".txt", ""))
        if stripped.startswith(b"#!"):
            return TypeInfo("sh", "Script com shebang", "script")
        if stripped.startswith(b"windows registry editor") or stripped.startswith(b"regedit4"):
            return TypeInfo("reg", "Arquivo de registro (.reg)", "script")
        return TypeInfo("text", "Texto", "text")
    return TypeInfo("data", "Dados binários", "data")


def _looks_like_text(h: bytes) -> bool:
    if not h:
        return False
    sample = h[:1024]
    if sample.startswith((b"\xff\xfe", b"\xfe\xff")):
        return True
    if b"\x00" in sample:
        return False
    printable = sum(1 for b in sample if 32 <= b < 127 or b in (9, 10, 13) or b >= 0x80)
    return printable / len(sample) > 0.95


def group_enabled(info: TypeInfo, ext: str, file_types: dict) -> bool:
    """Whether a file belongs to a group enabled in settings.scan.file_types."""
    kind = info.kind
    if kind in ("pe_dll", "pe_dotnet_dll"):
        return file_types.get("libraries", True)
    if kind == "pe_sys":
        return file_types.get("drivers", True)
    if info.group == "executable":
        return file_types.get("executables", True)
    if info.group == "script":
        return file_types.get("scripts", True)
    if kind == "jar" or kind == "java_class":
        return file_types.get("java", True)
    if kind == "msi":
        return file_types.get("installers", True)
    if info.group == "archive":
        return file_types.get("archives", True)
    if info.group == "shortcut":
        return file_types.get("shortcuts", True)
    return file_types.get("data_sniffing", True)


def priority(info: TypeInfo, ext: str, name: str) -> int:
    """Lower value = analysed first. Executables, loaders and scripts come first."""
    lname = name.lower()
    if info.disguised:
        return 0
    if info.group == "executable":
        if any(k in lname for k in ("crack", "keygen", "patch", "loader", "launcher", "setup", "install", "steam_api")):
            return 1
        return 2
    if info.group == "script" or info.group == "shortcut":
        return 3
    if info.group == "archive":
        return 4
    if info.group in ("document", "text"):
        return 6
    return 8
