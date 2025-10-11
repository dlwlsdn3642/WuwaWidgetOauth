import ctypes as C
import ctypes.wintypes as W
import re
import socket
import sys
import time
from contextlib import contextmanager
import psutil

# --- 설정 및 상수 ---
HOST = "pc-launcher-sdk-api.kurogame.net"
TARGET_PROC = "msedgewebview2.exe"
OAUTH_REGEX = re.compile(rb'"oauthCode"\s*:\s*"([0-9a-f-]{36})"', re.IGNORECASE)

# --- Windows API 정의 ---
kernel32 = C.WinDLL("kernel32", use_last_error=True)
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
MEM_COMMIT = 0x1000
PAGE_NOACCESS = 0x01
PAGE_GUARD = 0x100


class MEMORY_BASIC_INFORMATION(C.Structure):
    _fields_ = [
        ("BaseAddress", W.LPVOID),
        ("AllocationBase", W.LPVOID),
        ("AllocationProtect", W.DWORD),
        ("RegionSize", C.c_size_t),
        ("State", W.DWORD),
        ("Protect", W.DWORD),
        ("Type", W.DWORD),
    ]


# 함수 프로토타입 설정
VirtualQueryEx = kernel32.VirtualQueryEx
VirtualQueryEx.argtypes = [
    W.HANDLE,
    W.LPCVOID,
    C.POINTER(MEMORY_BASIC_INFORMATION),
    C.c_size_t,
]
VirtualQueryEx.restype = C.c_size_t

ReadProcessMemory = kernel32.ReadProcessMemory
ReadProcessMemory.argtypes = [
    W.HANDLE,
    W.LPCVOID,
    W.LPVOID,
    C.c_size_t,
    C.POINTER(C.c_size_t),
]
ReadProcessMemory.restype = W.BOOL


@contextmanager
def open_process(pid):
    h_process = kernel32.OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid
    )
    if not h_process:
        yield None
        return
    try:
        yield h_process
    finally:
        kernel32.CloseHandle(h_process)


def find_target_pids(ips):
    """대상 프로세스(msedgewebview2.exe)의 PID 목록을 찾아서 반환.
    psutil이 있으면 IP에 연결된 PID를 우선순위로 정렬."""
    all_pids = set()
    if psutil:
        for p in psutil.process_iter(["pid", "name"]):
            if (p.info.get("name") or "").lower() == TARGET_PROC:
                all_pids.add(p.info["pid"])
    else:
        import subprocess

        try:
            out = subprocess.check_output(
                ["tasklist", "/FI", f"IMAGENAME eq {TARGET_PROC}"], text=True
            )
            for line in out.splitlines():
                if TARGET_PROC.lower() in line.lower():
                    parts = line.split()
                    if parts and parts[1].isdigit():
                        all_pids.add(int(parts[1]))
        except Exception:
            pass

    if not psutil or not ips:
        return sorted(list(all_pids))
    connected_pids = set()
    try:
        for c in psutil.net_connections(kind="inet"):
            if (
                c.pid in all_pids
                and c.raddr
                and c.raddr.ip in ips
                and c.raddr.port == 443
                and c.status == psutil.CONN_ESTABLISHED
            ):
                connected_pids.add(c.pid)
    except psutil.Error:
        pass
    return sorted(list(connected_pids)) + sorted(list(all_pids - connected_pids))


def scan_process_for_oauth(pid, max_bytes_to_scan=256 * 1024 * 1024):
    """프로세스 메모리에서 oauthCode 패턴을 검색"""
    found_codes = set()
    with open_process(pid) as h_process:
        if not h_process:
            return found_codes

        addr = 0
        scanned_bytes = 0
        mbi = MEMORY_BASIC_INFORMATION()
        chunk_size = 4 * 1024 * 1024
        buffer = (C.c_char * chunk_size)()
        bytes_read = C.c_size_t(0)

        while kernel32.VirtualQueryEx(
            h_process, C.c_void_p(addr), C.byref(mbi), C.sizeof(mbi)
        ):
            region_addr = mbi.BaseAddress
            region_size = mbi.RegionSize
            addr += region_size
            is_readable = mbi.State == MEM_COMMIT and not (
                mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)
            )
            if not is_readable:
                continue

            offset = 0
            while offset < region_size and scanned_bytes < max_bytes_to_scan:
                bytes_to_read = min(chunk_size, region_size - offset)
                if ReadProcessMemory(
                    h_process,
                    C.c_void_p(region_addr + offset),
                    buffer,
                    bytes_to_read,
                    C.byref(bytes_read),
                ):
                    if bytes_read.value == 0:
                        break
                    data = C.string_at(C.addressof(buffer), bytes_read.value)
                    for match in OAUTH_REGEX.finditer(data):
                        found_codes.add(match.group(1).decode("ascii", "ignore"))
                    scanned_bytes += bytes_read.value
                else:
                    break
                offset += chunk_size
    return found_codes


def main():
    print("[*] Resolving host IPs...")
    try:
        ips = {
            addr[4][0]
            for addr in socket.getaddrinfo(HOST, 443)
            if addr[0] in (socket.AF_INET, socket.AF_INET6)
        }
        print(f"    -> {HOST} : {', '.join(ips) or '(not found)'}")
    except socket.gaierror:
        ips = set()
        print(f"    -> Failed to resolve {HOST}")

    print("[*] Finding target processes...")
    pids = find_target_pids(ips)
    if not pids:
        print("[-] No msedgewebview2 processes found.")
        sys.exit(1)

    print(f"    -> Found {len(pids)} candidate(s): {pids}")
    print("[*] Scanning processes (run as Administrator for best results)...")

    all_found_codes = set()
    for pid in pids:
        print(f"    - PID {pid} ...", end="", flush=True)
        start_time = time.time()
        found = scan_process_for_oauth(pid)
        duration = time.time() - start_time
        if found:
            print(f" found {len(found)} code(s) in {duration:.1f}s")
            all_found_codes.update(found)
            break
        else:
            print(f" none ({duration:.1f}s)")

    if all_found_codes:
        print("\n[+] oauthCode(s) detected:")
        sorted_codes = sorted(all_found_codes)
        for code in sorted_codes:
            print("    ", code)
        try:
            with open("oauthCode.txt", "w") as f:
                f.write("\n".join(sorted_codes) + "\n")
            print("[+] Saved to oauthCode.txt")
        except IOError as e:
            print(f"[!] Save failed: {e}")
    else:
        print("\n[-] No oauthCode pattern found. Tips:")
        print("    • Run this script immediately after the launcher widget refreshes.")
        print("    • Ensure you are running this as an Administrator.")
        print("    • Antivirus/EDR software might block memory reading.")
        if not psutil:
            print("    • For better accuracy, install psutil: pip install psutil")
        sys.exit(2)


if __name__ == "__main__":
    main()
