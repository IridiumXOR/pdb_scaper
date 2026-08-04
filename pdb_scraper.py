#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
download_winbindex_pdb.py

Given a Windows binary filename, query https://winbindex.m417z.com for every
indexed version of that file across the x64, ARM64 and Insider-Preview data
sources, download each binary from the Microsoft symbol server, then try to
fetch the matching PDB using the pyPDBdownload (pdbdownload) logic.

A version is kept ONLY if its PDB exists: the binary and its PDB are stored
together in a per-version directory. If the PDB cannot be found, both the
binary and the (missing) PDB are discarded.

Winbindex has three separate data roots (mirroring the site's ?arch= switch):

    x64/x86 : https://winbindex.m417z.com/data/by_filename_compressed/<name>.json.gz
    arm64   : https://m417z.com/winbindex-data-arm64/by_filename_compressed/<name>.json.gz
    insider : https://m417z.com/winbindex-data-insider/by_filename_compressed/<shard>/<name>.json.gz

The insider root shards files into sub-directories named after
(djb2Hash(filename) & 0xFF) as a 2-digit hex string, exactly as the frontend does.

Symbol-server binary URL (built from fileInfo.timestamp + fileInfo.virtualSize):
    https://msdl.microsoft.com/download/symbols/<name>/<TimeDateStamp:08X><SizeOfImage:X>/<name>

When virtualSize is missing (delta-indexed entries), Winbindex's Download button
generates several SizeOfImage candidate URLs from delta metadata (size,
lastSectionPointerToRawData, lastSectionVirtualAddress) using the same algorithm
as DeltaDownloader / winbindex.js onMultiDownloadClick. This script reproduces
that list and HEAD-probes candidates until one exists on the symbol server.

PDB URL (built from the PE debug directory, via pyPDBdownload):
    https://msdl.microsoft.com/download/symbols/<pdb>/<GUID><age>/<pdb>
"""

import argparse
import gzip
import hashlib
import json
import os
import re
import shutil
import struct
import sys
import tempfile
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

import pefile
import requests

# Reuse pyPDBdownload's PE debug-info extractor so the PDB signature is computed
# exactly the same way the tool does (pip install pdbdownload).
try:
    from pdbdownload.__main__ import get_pe_debug_infos
except Exception as exc:  # pragma: no cover
    print("[!] Could not import pdbdownload. Install it with: pip install pdbdownload")
    print("    (%s)" % exc)
    sys.exit(1)


MSDL = "https://msdl.microsoft.com/download/symbols/%s/%s/%s"
# Same UA pyPDBdownload uses; the symbol server expects a symbol-server client.
SYMBOL_UA = {"User-Agent": "Microsoft-Symbol-Server/10.0.10036.206"}
WINBINDEX_UA = {"User-Agent": "winbindex-pdb-downloader"}

# IMAGE_FILE_MACHINE_* -> short architecture label
MACHINE_ARCH = {
    0x014C: "x86",     # I386
    0x8664: "amd64",   # AMD64 (x64)
    0x01C0: "arm",     # ARM
    0x01C4: "armnt",   # ARMNT (Thumb-2)
    0xAA64: "arm64",   # ARM64
    0x0200: "ia64",    # IA64
}

# thread-local requests session -> connection pooling per worker
_local = threading.local()


def session():
    s = getattr(_local, "session", None)
    if s is None:
        s = requests.Session()
        s.headers.update(SYMBOL_UA)
        _local.session = s
    return s


# --------------------------------------------------------------------------- #
# Winbindex data sources
# --------------------------------------------------------------------------- #

def _to_int32(n):
    n &= 0xFFFFFFFF
    return n - 0x100000000 if n >= 0x80000000 else n


def djb2_hash(s):
    """djb2, replicated from winbindex.js (ToInt32 on the shift, uint32 result)."""
    h = 5381
    for ch in s:
        h = _to_int32((_to_int32(h) << 5) & 0xFFFFFFFF) + h + ord(ch)
    return h & 0xFFFFFFFF


def insider_shard(filename):
    return format(djb2_hash(filename) & 0xFF, "02x")


def source_url(source, filename):
    """Return the by_filename_compressed .json.gz URL for a given data source."""
    if source == "x64":
        return "https://winbindex.m417z.com/data/by_filename_compressed/%s.json.gz" % filename
    if source == "arm64":
        return "https://m417z.com/winbindex-data-arm64/by_filename_compressed/%s.json.gz" % filename
    if source == "insider":
        return ("https://m417z.com/winbindex-data-insider/by_filename_compressed/%s/%s.json.gz"
                % (insider_shard(filename), filename))
    raise ValueError("unknown source %r" % source)


ALL_SOURCES = ["x64", "arm64", "insider"]


# --------------------------------------------------------------------------- #
# PE analysis
# --------------------------------------------------------------------------- #

# Size (bytes) of one RUNTIME_FUNCTION entry in the exception (.pdata) directory,
# per machine type. x86 has no such table (its SEH is frame-based).
PDATA_ELEM_SIZE = {
    0x8664: 12,   # AMD64: BeginAddress, EndAddress, UnwindInfoAddress
    0xAA64: 8,    # ARM64: FunctionStart RVA + packed/unwind data
    0x01C4: 8,    # ARMNT
    0x01C0: 8,    # ARM
}


def analyze_pe(path):
    """Extract per-EXE metrics.

    A release PE only carries a *function table* (the exception directory); it
    has no type or global-variable symbol information -- that lives in the PDB.
    So `types` / `global_variables` are reported as null for the binary.
    """
    result = {"functions": None, "types": None, "global_variables": None,
              "exported_symbols": 0}
    pe = pefile.PE(path, fast_load=True)
    try:
        machine = pe.FILE_HEADER.Machine
        dd = {d.name: d for d in pe.OPTIONAL_HEADER.DATA_DIRECTORY}
        exc = dd.get("IMAGE_DIRECTORY_ENTRY_EXCEPTION")
        elem = PDATA_ELEM_SIZE.get(machine)
        if exc is not None and exc.Size and elem:
            result["functions"] = exc.Size // elem
        try:
            pe.parse_data_directories(
                directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]])
            if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
                result["exported_symbols"] = len(pe.DIRECTORY_ENTRY_EXPORT.symbols)
        except Exception:
            pass
    finally:
        pe.close()
    return result


# --------------------------------------------------------------------------- #
# PDB analysis  (self-contained MSF 7.0 / CodeView parser, validated against
# llvm-pdbutil).  Counts type records (TPI), function symbols and global/static
# data symbols across the module, global and public symbol streams.
# --------------------------------------------------------------------------- #

_MSF_MAGIC = b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\x00\x00\x00"

# CodeView symbol record kinds we care about.
S_LDATA32 = 0x110C
S_GDATA32 = 0x110D
S_PUB32 = 0x110E
S_LPROC32 = 0x110F
S_GPROC32 = 0x1110
S_PROCREF = 0x1125
S_LPROCREF = 0x1127
CVPSF_FUNCTION = 0x2  # S_PUB32 flag: symbol refers to a function


class _Msf:
    """Minimal Multi-Stream-Format (MSF 7.0 / "DS") reader."""

    def __init__(self, data):
        if data[:len(_MSF_MAGIC)] != _MSF_MAGIC:
            raise ValueError("not an MSF 7.0 (DS) container")
        (self.block_size, _free, self.num_blocks, self.num_dir_bytes,
         _unknown, self.block_map_addr) = struct.unpack_from("<6I", data, 32)
        self.data = data
        self.streams = self._read_directory()

    def _block(self, idx):
        off = idx * self.block_size
        return self.data[off:off + self.block_size]

    def _concat(self, indices, size):
        return b"".join(self._block(i) for i in indices)[:size]

    def _read_directory(self):
        bs = self.block_size
        n_dir_blocks = (self.num_dir_bytes + bs - 1) // bs
        map_block = self._block(self.block_map_addr)
        dir_block_idx = struct.unpack_from("<%dI" % n_dir_blocks, map_block, 0)
        directory = self._concat(dir_block_idx, self.num_dir_bytes)
        pos = 0
        num_streams = struct.unpack_from("<I", directory, pos)[0]
        pos += 4
        sizes = []
        for _ in range(num_streams):
            s = struct.unpack_from("<I", directory, pos)[0]
            pos += 4
            sizes.append(0 if s == 0xFFFFFFFF else s)
        streams = []
        for size in sizes:
            nb = (size + bs - 1) // bs
            idxs = list(struct.unpack_from("<%dI" % nb, directory, pos)) if nb else []
            pos += nb * 4
            streams.append((size, idxs))
        return streams

    def stream(self, index):
        if index == 0xFFFF or index >= len(self.streams):
            return b""
        size, idxs = self.streams[index]
        return self._concat(idxs, size)


def _iter_symbols(buf, start=0, end=None):
    """Yield (kind, record_bytes) for each CodeView symbol record."""
    if end is None:
        end = len(buf)
    end = min(end, len(buf))
    pos = start
    while pos + 4 <= end:
        reclen, kind = struct.unpack_from("<HH", buf, pos)
        if reclen < 2:
            break
        yield kind, buf[pos + 4:pos + 2 + reclen]
        pos += reclen + 2


def analyze_pdb(path):
    """Extract per-PDB metrics: functions, types, global variables."""
    msf = _Msf(open(path, "rb").read())

    # --- types: number of records in the TPI stream (stream #2) ---
    type_records = 0
    tpi = msf.stream(2)
    if len(tpi) >= 16:
        _ver, _hdr, ti_begin, ti_end = struct.unpack_from("<4I", tpi, 0)
        type_records = max(0, ti_end - ti_begin)

    proc = data = pub = pub_func = 0
    dbi = msf.stream(3)
    if len(dbi) >= 64:
        hdr = struct.unpack_from("<iIIHHHHHHiiiiiIiiHHI", dbi, 0)
        sym_record_stream = hdr[7]
        modinfo_size = hdr[9]

        # --- per-module symbol streams: real S_GPROC32 / S_LPROC32 defs ---
        modinfo = dbi[64:64 + modinfo_size]
        pos, n = 0, len(modinfo)
        while pos + 64 <= n:
            mod_stream = struct.unpack_from("<H", modinfo, pos + 34)[0]
            sym_size = struct.unpack_from("<I", modinfo, pos + 36)[0]
            p = pos + 64
            try:
                p = modinfo.index(b"\x00", p) + 1   # module name
                p = modinfo.index(b"\x00", p) + 1   # obj file name
            except ValueError:
                break
            p = (p + 3) & ~3
            if mod_stream != 0xFFFF and sym_size > 4:
                sbuf = msf.stream(mod_stream)
                for kind, _rec in _iter_symbols(sbuf, 4, sym_size):
                    if kind in (S_GPROC32, S_LPROC32):
                        proc += 1
                    elif kind in (S_GDATA32, S_LDATA32):
                        data += 1
            pos = p

        # --- global + public symbol record stream ---
        for kind, rec in _iter_symbols(msf.stream(sym_record_stream)):
            if kind == S_PUB32:
                pub += 1
                flags = struct.unpack_from("<I", rec, 0)[0] if len(rec) >= 4 else 0
                if flags & CVPSF_FUNCTION:
                    pub_func += 1
            elif kind in (S_GDATA32, S_LDATA32):
                data += 1

    # Headline function count: procedures if the PDB is "private", otherwise the
    # public function symbols (stripped Microsoft PDBs only expose publics).
    functions = max(proc, pub_func)
    return {
        "functions": functions,
        "types": type_records,
        "global_variables": data,
        "detail": {
            "proc_symbols": proc,          # S_GPROC32 + S_LPROC32
            "public_functions": pub_func,  # S_PUB32 flagged as function
            "public_symbols": pub,         # all S_PUB32
            "data_symbols": data,          # S_GDATA32 + S_LDATA32
            "type_records": type_records,
            "stripped": (proc == 0 and type_records == 0),
        },
    }


def analyze_files(bin_path, pdb_path):
    """Run PE + PDB analysis, never raising into the download pipeline."""
    try:
        exe = analyze_pe(bin_path)
    except Exception as exc:
        exe = {"functions": None, "types": None, "global_variables": None,
               "error": "%s: %s" % (type(exc).__name__, exc)}
    try:
        pdb = analyze_pdb(pdb_path)
    except Exception as exc:
        pdb = {"functions": None, "types": None, "global_variables": None,
               "error": "%s: %s" % (type(exc).__name__, exc)}
    return {"exe": exe, "pdb": pdb}


# --------------------------------------------------------------------------- #
# Logging / counters
# --------------------------------------------------------------------------- #

class Counters:
    """Thread-safe tally + logging."""

    def __init__(self):
        self.lock = threading.Lock()
        self.kept = 0
        self.no_pdb = 0
        self.no_binary = 0
        self.skipped = 0
        self.errors = 0

    def log(self, msg):
        with self.lock:
            print(msg, flush=True)


COUNTERS = Counters()


def machine_arch(machine_type):
    return MACHINE_ARCH.get(machine_type, "unknown")


def sanitize(name):
    """Make a string safe to use as a directory name."""
    name = re.sub(r"[^A-Za-z0-9._+-]+", "_", name.strip())
    return name.strip("_") or "unknown"


def fetch_source(filename, source, timeout=60):
    """Download+decompress the winbindex JSON for `filename` from one source.

    Returns {} when the file is not indexed in that source (HTTP 404)."""
    url = source_url(source, filename)
    r = requests.get(url, headers=WINBINDEX_UA, timeout=timeout)
    if r.status_code == 200:
        return json.loads(gzip.decompress(r.content))
    if r.status_code == 404:
        return {}
    raise RuntimeError("%s source returned HTTP %d for %r" % (source, r.status_code, filename))


def gather_entries(filename, sources):
    """Fetch every requested source and merge entries by sha256.

    Returns {sha256: {"entry": entry, "sources": set, "osversions": set}}."""
    merged = {}
    for source in sources:
        try:
            data = fetch_source(filename, source)
        except Exception as exc:
            COUNTERS.log("[!] %s" % exc)
            continue
        count = 0
        for sha256, entry in data.items():
            if not entry.get("fileInfo"):
                continue
            count += 1
            slot = merged.get(sha256)
            osk = set(entry.get("windowsVersions", {}).keys())
            if slot is None:
                merged[sha256] = {"entry": entry, "sources": {source}, "osversions": osk}
            else:
                slot["sources"].add(source)
                slot["osversions"] |= osk
        COUNTERS.log("[>] source %-8s: %d downloadable version(s)" % (source, count))
    return merged


# --------------------------------------------------------------------------- #
# Download helpers
# --------------------------------------------------------------------------- #

def build_binary_url(filename, timestamp, virtual_size):
    seg = "%08X%X" % (timestamp, virtual_size)
    return MSDL % (filename, seg, filename)


PAGE_SIZE = 0x1000


def mapped_size(size):
    """Round `size` up to the next page boundary (DeltaDownloader GetMappedSize)."""
    page_mask = PAGE_SIZE - 1
    page = size & ~page_mask
    if page == size:
        return page
    return page + PAGE_SIZE


def delta_virtual_size_candidates(file_size, last_section_ptr, last_section_va):
    """Candidate SizeOfImage values from delta metadata (high -> low).

    Mirrors winbindex.js onMultiDownloadClick / DeltaDownloader Program.cs.
    """
    last_section_and_signature_size = file_size - last_section_ptr
    size_of_image = mapped_size(last_section_va + last_section_and_signature_size)
    lowest_size_of_image = last_section_va + PAGE_SIZE
    sizes = []
    size = size_of_image
    while size >= lowest_size_of_image:
        sizes.append(size)
        size -= PAGE_SIZE
    return sizes


def resolve_binary_url(filename, fi):
    """Resolve a symbol-server binary URL from winbindex fileInfo.

    Returns (url, virtual_size, method, candidate_urls) or None.
    method is "virtualSize" or "delta_candidates".
    """
    timestamp = fi.get("timestamp")
    if timestamp is None:
        return None

    virtual_size = fi.get("virtualSize")
    if virtual_size is not None:
        url = build_binary_url(filename, timestamp, virtual_size)
        return url, virtual_size, "virtualSize", []

    file_size = fi.get("size")
    last_ptr = fi.get("lastSectionPointerToRawData")
    last_va = fi.get("lastSectionVirtualAddress")
    if file_size is None or last_ptr is None or last_va is None:
        return None

    sizes = delta_virtual_size_candidates(file_size, last_ptr, last_va)
    candidate_urls = [build_binary_url(filename, timestamp, s) for s in sizes]
    for size, url in zip(sizes, candidate_urls):
        exists, _ = head_ok(url)
        if exists:
            return url, size, "delta_candidates", candidate_urls
    return None


def stream_download(url, dest_path, timeout=120):
    """Download `url` to `dest_path`. Returns (ok, size, status)."""
    r = session().get(url, stream=True, allow_redirects=True, timeout=timeout)
    if r.status_code != 200:
        r.close()
        return False, 0, r.status_code
    size = 0
    with open(dest_path, "wb") as f:
        for chunk in r.iter_content(chunk_size=1024 * 64):
            if chunk:
                f.write(chunk)
                size += len(chunk)
    return True, size, 200


def head_ok(url, timeout=60):
    """Return (exists, resolved_url)."""
    r = session().head(url, allow_redirects=True, timeout=timeout)
    return (r.status_code == 200), r.url


def process_entry(filename, sha256, slot, outdir, overwrite):
    """Download binary + PDB for one merged entry. Keep only if the PDB exists."""
    entry = slot["entry"]
    fi = entry.get("fileInfo") or {}
    version = fi.get("version") or "unknown"
    arch = machine_arch(fi.get("machineType"))
    srclabel = "+".join(sorted(slot["sources"]))
    label = "%s [%s/%s] %s" % (version, arch, srclabel, sha256[:8])

    # Enough metadata to attempt a symbol-server URL? (exact or delta candidates)
    timestamp = fi.get("timestamp")
    has_exact = timestamp is not None and fi.get("virtualSize") is not None
    has_delta = (
        timestamp is not None
        and fi.get("size") is not None
        and fi.get("lastSectionPointerToRawData") is not None
        and fi.get("lastSectionVirtualAddress") is not None
    )
    if not has_exact and not has_delta:
        return

    dir_name = "%s_%s_%s" % (sanitize(version), arch, sha256[:8])
    dest_dir = os.path.join(outdir, dir_name)
    bin_path = os.path.join(dest_dir, filename)

    if not overwrite and os.path.isdir(dest_dir) and os.listdir(dest_dir):
        COUNTERS.log("[=] skip (exists) %s" % label)
        with COUNTERS.lock:
            COUNTERS.skipped += 1
        return

    resolved = resolve_binary_url(filename, fi)
    if resolved is None:
        COUNTERS.log("[-] no binary (delta candidates missed) %s" % label)
        with COUNTERS.lock:
            COUNTERS.no_binary += 1
        return

    bin_url, virtual_size, resolve_method, candidate_urls = resolved

    tmp_bin = None
    try:
        # 1) fetch the binary to a temp file first (needed to read the PDB signature)
        fd, tmp_bin = tempfile.mkstemp(prefix="winbindex_", suffix="_" + filename)
        os.close(fd)
        ok, size, status = stream_download(bin_url, tmp_bin)
        if not ok:
            COUNTERS.log("[-] no binary (HTTP %s) %s" % (status, label))
            with COUNTERS.lock:
                COUNTERS.no_binary += 1
            return

        # 2) read PDB name + signature (GUID+age) from the PE debug directory
        try:
            pdbname, signature = get_pe_debug_infos(tmp_bin)
        except Exception as exc:
            COUNTERS.log("[-] no debug info (%s) %s" % (exc, label))
            with COUNTERS.lock:
                COUNTERS.no_pdb += 1
            return

        # 3) check whether the PDB exists on the symbol server
        pdb_url = MSDL % (pdbname, signature.upper(), pdbname)
        exists, resolved_pdb = head_ok(pdb_url)
        if not exists:
            COUNTERS.log("[-] no PDB %s (%s)" % (label, pdbname))
            with COUNTERS.lock:
                COUNTERS.no_pdb += 1
            return  # discard both binary and pdb

        # 4) PDB exists -> commit: create dir, move binary in, download PDB
        os.makedirs(dest_dir, exist_ok=True)
        shutil.move(tmp_bin, bin_path)
        tmp_bin = None  # moved, don't clean up

        pdb_path = os.path.join(dest_dir, pdbname)
        ok, psize, pstatus = stream_download(resolved_pdb, pdb_path)
        if not ok:
            COUNTERS.log("[-] PDB vanished (HTTP %s) %s" % (pstatus, label))
            shutil.rmtree(dest_dir, ignore_errors=True)
            with COUNTERS.lock:
                COUNTERS.no_pdb += 1
            return

        meta = {
            "filename": filename,
            "sha256": sha256,
            "version": version,
            "architecture": arch,
            "machineType": fi.get("machineType"),
            "timestamp": timestamp,
            "virtualSize": virtual_size,
            "binaryResolveMethod": resolve_method,
            "binaryCandidateUrls": candidate_urls,
            "sources": sorted(slot["sources"]),
            "windowsVersions": sorted(slot["osversions"]),
            "binaryUrl": bin_url,
            "pdbName": pdbname,
            "pdbSignature": signature,
            "pdbUrl": pdb_url,
            "binarySize": size,
            "pdbSize": psize,
            "analysis": analyze_files(bin_path, pdb_path),
        }
        with open(os.path.join(dest_dir, "metadata.json"), "w") as f:
            json.dump(meta, f, indent=2)

        method_note = "" if resolve_method == "virtualSize" else " (delta)"
        COUNTERS.log("[+] kept %s -> %s%s" % (label, dir_name, method_note))
        with COUNTERS.lock:
            COUNTERS.kept += 1
    except Exception as exc:
        COUNTERS.log("[!] error %s: %s" % (label, exc))
        with COUNTERS.lock:
            COUNTERS.errors += 1
    finally:
        if tmp_bin and os.path.exists(tmp_bin):
            try:
                os.remove(tmp_bin)
            except OSError:
                pass


# --------------------------------------------------------------------------- #
# Local-directory mode
# --------------------------------------------------------------------------- #

DEFAULT_EXTS = [".exe", ".dll", ".sys"]


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 256), b""):
            h.update(chunk)
    return h.hexdigest()


def pe_identity(path):
    """Return (machineType, version_string) read from the PE itself."""
    pe = pefile.PE(path, fast_load=True)
    try:
        machine = pe.FILE_HEADER.Machine
        version = "unknown"
        try:
            pe.parse_data_directories(
                directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"]])
            ffi = getattr(pe, "VS_FIXEDFILEINFO", None)
            if ffi:
                f = ffi[0]
                version = "%d.%d.%d.%d" % (
                    f.FileVersionMS >> 16, f.FileVersionMS & 0xFFFF,
                    f.FileVersionLS >> 16, f.FileVersionLS & 0xFFFF)
        except Exception:
            pass
    finally:
        pe.close()
    return machine, version


def find_pe_files(input_dir, exts):
    found = []
    for root, _dirs, files in os.walk(input_dir):
        for fn in files:
            if os.path.splitext(fn)[1].lower() in exts:
                found.append(os.path.join(root, fn))
    return sorted(found)


def process_local_file(path, outdir, overwrite, arch_filter):
    """Look up + fetch the PDB for one local PE, organizing it like winbindex mode.

    The user's original file is COPIED (never moved); if no PDB exists nothing is
    written and the original is left untouched."""
    filename = os.path.basename(path)
    try:
        machine, version = pe_identity(path)
    except Exception as exc:
        COUNTERS.log("[-] not a PE (%s) %s" % (exc, filename))
        return  # silently ignore non-PE files in the tree

    arch = machine_arch(machine)
    if arch_filter is not None and arch not in arch_filter:
        return

    label = "%s [%s] %s" % (version, arch, filename)
    try:
        sha256 = sha256_file(path)
    except Exception as exc:
        COUNTERS.log("[!] error %s: %s" % (label, exc))
        with COUNTERS.lock:
            COUNTERS.errors += 1
        return

    dir_name = "%s_%s_%s" % (sanitize(version), arch, sha256[:8])
    dest_dir = os.path.join(outdir, dir_name)
    if not overwrite and os.path.isdir(dest_dir) and os.listdir(dest_dir):
        COUNTERS.log("[=] skip (exists) %s" % label)
        with COUNTERS.lock:
            COUNTERS.skipped += 1
        return

    try:
        # 1) read PDB name + signature from the local PE's debug directory
        try:
            pdbname, signature = get_pe_debug_infos(path)
        except Exception as exc:
            COUNTERS.log("[-] no debug info (%s) %s" % (exc, label))
            with COUNTERS.lock:
                COUNTERS.no_pdb += 1
            return

        # 2) does the PDB exist on the symbol server?
        pdb_url = MSDL % (pdbname, signature.upper(), pdbname)
        exists, resolved = head_ok(pdb_url)
        if not exists:
            COUNTERS.log("[-] no PDB %s (%s)" % (label, pdbname))
            with COUNTERS.lock:
                COUNTERS.no_pdb += 1
            return  # leave the user's original in place, write nothing

        # 3) PDB exists -> copy the binary in, download the PDB, analyze
        os.makedirs(dest_dir, exist_ok=True)
        bin_path = os.path.join(dest_dir, filename)
        shutil.copy2(path, bin_path)  # copy, never move the source file

        pdb_path = os.path.join(dest_dir, pdbname)
        ok, psize, pstatus = stream_download(resolved, pdb_path)
        if not ok:
            COUNTERS.log("[-] PDB vanished (HTTP %s) %s" % (pstatus, label))
            shutil.rmtree(dest_dir, ignore_errors=True)
            with COUNTERS.lock:
                COUNTERS.no_pdb += 1
            return

        meta = {
            "filename": filename,
            "sha256": sha256,
            "version": version,
            "architecture": arch,
            "machineType": machine,
            "sources": ["local"],
            "sourcePath": os.path.abspath(path),
            "pdbName": pdbname,
            "pdbSignature": signature,
            "pdbUrl": pdb_url,
            "binarySize": os.path.getsize(bin_path),
            "pdbSize": psize,
            "analysis": analyze_files(bin_path, pdb_path),
        }
        with open(os.path.join(dest_dir, "metadata.json"), "w") as f:
            json.dump(meta, f, indent=2)

        COUNTERS.log("[+] kept %s -> %s" % (label, dir_name))
        with COUNTERS.lock:
            COUNTERS.kept += 1
    except Exception as exc:
        COUNTERS.log("[!] error %s: %s" % (label, exc))
        with COUNTERS.lock:
            COUNTERS.errors += 1


def parse_args():
    p = argparse.ArgumentParser(
        description="Fetch PDBs for Windows binaries -- either every winbindex "
                    "version of a file (x64/arm64/insider) or every PE in a local "
                    "directory -- keeping only versions whose PDB exists.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("filename", nargs="?",
                   help="winbindex mode: binary filename to look up, "
                        "e.g. 'ntoskrnl.exe'. Omit when using -i/--input-dir.")
    p.add_argument("-i", "--input-dir", default=None,
                   help="local mode: take PE files from this directory (recursively) "
                        "instead of downloading them from winbindex.")
    p.add_argument("--ext", action="append",
                   help="local mode: file extension(s) to treat as PE (repeatable). "
                        "Default: %s." % " ".join(DEFAULT_EXTS))
    p.add_argument("-o", "--output-dir", default="./winbindex_output",
                   help="Root directory; one sub-directory is created per kept version.")
    p.add_argument("-s", "--source", action="append", choices=ALL_SOURCES,
                   help="Winbindex data source(s) to query (repeatable). Default: all three.")
    p.add_argument("-a", "--arch", action="append", choices=sorted(set(MACHINE_ARCH.values())),
                   help="Restrict to these PE architecture(s) (repeatable). "
                        "Default: keep everything each source returns.")
    p.add_argument("-t", "--threads", type=int, default=8,
                   help="Number of concurrent download workers.")
    p.add_argument("--overwrite", action="store_true",
                   help="Re-download even if a version directory already exists.")
    return p.parse_args()


def print_summary():
    print("\n=== Summary ===")
    print("  kept (binary+pdb) : %d" % COUNTERS.kept)
    print("  no PDB (discarded): %d" % COUNTERS.no_pdb)
    print("  no binary         : %d" % COUNTERS.no_binary)
    print("  skipped (existing): %d" % COUNTERS.skipped)
    print("  errors            : %d" % COUNTERS.errors)


def run_winbindex(args, arch_filter):
    sources = args.source if args.source else ALL_SOURCES
    print("[>] Mode     : winbindex")
    print("[>] Filename : %s" % args.filename)
    print("[>] Sources  : %s" % ", ".join(sources))
    print("[>] Arch     : %s" % (", ".join(sorted(arch_filter)) if arch_filter else "all"))
    print("[>] Output   : %s" % os.path.abspath(args.output_dir))
    print("[>] Threads  : %d\n" % args.threads)

    merged = gather_entries(args.filename, sources)
    if arch_filter is not None:
        merged = {
            sha: slot for sha, slot in merged.items()
            if machine_arch((slot["entry"].get("fileInfo") or {}).get("machineType")) in arch_filter
        }

    print("\n[>] %d unique version(s) to process\n" % len(merged))
    if not merged:
        print("[!] Nothing to do.")
        return

    os.makedirs(args.output_dir, exist_ok=True)
    with ThreadPoolExecutor(max_workers=args.threads) as pool:
        futures = [
            pool.submit(process_entry, args.filename, sha, slot, args.output_dir, args.overwrite)
            for sha, slot in merged.items()
        ]
        for _ in as_completed(futures):
            pass
    print_summary()


def run_local(args, arch_filter):
    exts = set((e if e.startswith(".") else "." + e).lower()
               for e in (args.ext or DEFAULT_EXTS))
    input_dir = os.path.abspath(args.input_dir)
    print("[>] Mode     : local directory")
    print("[>] Input    : %s" % input_dir)
    print("[>] Ext      : %s" % ", ".join(sorted(exts)))
    print("[>] Arch     : %s" % (", ".join(sorted(arch_filter)) if arch_filter else "all"))
    print("[>] Output   : %s" % os.path.abspath(args.output_dir))
    print("[>] Threads  : %d\n" % args.threads)

    if not os.path.isdir(input_dir):
        print("[!] Not a directory: %s" % input_dir)
        sys.exit(1)

    files = find_pe_files(input_dir, exts)
    print("[>] %d candidate PE file(s) to process\n" % len(files))
    if not files:
        print("[!] Nothing to do.")
        return

    os.makedirs(args.output_dir, exist_ok=True)
    with ThreadPoolExecutor(max_workers=args.threads) as pool:
        futures = [
            pool.submit(process_local_file, p, args.output_dir, args.overwrite, arch_filter)
            for p in files
        ]
        for _ in as_completed(futures):
            pass
    print_summary()


def main():
    args = parse_args()
    arch_filter = set(args.arch) if args.arch else None

    if bool(args.filename) == bool(args.input_dir):
        print("[!] Provide either a FILENAME (winbindex mode) or -i/--input-dir "
              "(local mode), not both.")
        sys.exit(2)

    if args.input_dir:
        run_local(args, arch_filter)
    else:
        run_winbindex(args, arch_filter)


if __name__ == "__main__":
    main()
