#!/usr/bin/env python3
"""The Endurance - show risk monitor (QLab cue timers, CPU, RAM, heaviest apps, other Macs with QLab)
served as a web page, designed for Safari on iPhone. /osc page: OSC message monitor.
Standard library only, no installation.

Usage:  python3 endurance.py
Then open on the iPhone:  http://MAC-IP:8080
"""
VERSION = "0.9.0"

import ctypes
import ipaddress
import json
import os
import plistlib
import re
import shutil
import socket
import struct
import subprocess
import sys
import threading
import time
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# ---- Impostazioni -----------------------------------------------------
QLAB_HOST = "127.0.0.1"   # if the script runs on the same Mac as QLab
QLAB_PORT = 53000         # QLab OSC port. TCP is used: port 53001 (also used by Companion) is not needed
PASSCODE = ""             # OSC passcode of the workspace, if any
HTTP_PORT = 8080
# Reading intervals (seconds). Recommended values in brackets.
# They can be changed from the app's start window ("Times"), or here.
# Values that are too low can use system resources.


def _env_num(name, default, lo, hi):
    try:
        v = float(os.environ.get(name, "").replace(",", "."))
        return min(hi, max(lo, v))
    except ValueError:
        return default


SYS_INTERVAL = _env_num("DP_SYS", 1.0, 1.0, 120.0)     # CPU, RAM, pressione, swap (1)
APPS_SECONDS = _env_num("DP_APPS", 5.0, 1.0, 120.0)    # elenco app (5)
POLL_SECONDS = _env_num("DP_QLAB", 0.25, 0.05, 5.0)    # QLab cue timers (0.25)
PEERS_SECONDS = _env_num("DP_PEERS", 15.0, 5.0, 300.0)  # search for other Macs with QLab on the network (15)
SYS_SECONDS = max(0.0, SYS_INTERVAL - 1.0)             # pause: the CPU measurement takes ~1 s
# Other Macs with QLab to always check, for example on another network: ["10.0.5.20"]
# (or the environment variable DP_EXTRA="10.0.5.20,10.0.5.21"). The automatic search
# only looks at the private networks this Mac is connected to.
EXTRA_PEERS = []
# -----------------------------------------------------------------------


def _pad(b: bytes) -> bytes:
    return b + b"\0" * (4 - len(b) % 4)


def osc_encode(address, *args):
    tags = ","
    data = b""
    for a in args:
        if isinstance(a, str):
            tags += "s"
            data += _pad(a.encode())
        elif isinstance(a, int):
            tags += "i"
            data += struct.pack(">i", a)
        elif isinstance(a, float):
            tags += "f"
            data += struct.pack(">f", a)
    return _pad(address.encode()) + _pad(tags.encode()) + data


def _read_str(buf, i):
    end = buf.index(b"\0", i)
    s = buf[i:end].decode(errors="replace")
    return s, (end + 4) // 4 * 4


def osc_decode(buf):
    address, i = _read_str(buf, 0)
    tags, i = _read_str(buf, i)
    args = []
    for t in tags[1:]:
        if t == "s":
            s, i = _read_str(buf, i)
            args.append(s)
        elif t == "i":
            args.append(struct.unpack(">i", buf[i:i + 4])[0])
            i += 4
        elif t == "f":
            args.append(struct.unpack(">f", buf[i:i + 4])[0])
            i += 4
    return address, args


# --- SLIP (OSC 1.1 over TCP, "double END" as QLab requires) ---
SLIP_END, SLIP_ESC, SLIP_ESC_END, SLIP_ESC_ESC = 0xC0, 0xDB, 0xDC, 0xDD


def slip_encode(packet):
    out = bytearray([SLIP_END])
    for byte in packet:
        if byte == SLIP_END:
            out += bytes([SLIP_ESC, SLIP_ESC_END])
        elif byte == SLIP_ESC:
            out += bytes([SLIP_ESC, SLIP_ESC_ESC])
        else:
            out.append(byte)
    out.append(SLIP_END)
    return bytes(out)


def slip_frames(buf):
    """Splits the TCP stream into OSC packets. Returns (packets, remainder to complete)."""
    parts = buf.split(bytes([SLIP_END]))
    rest = parts.pop()
    frames = []
    for p in parts:
        if not p:
            continue
        out, esc = bytearray(), False
        for byte in p:
            if esc:
                out.append(SLIP_END if byte == SLIP_ESC_END else SLIP_ESC if byte == SLIP_ESC_ESC else byte)
                esc = False
            elif byte == SLIP_ESC:
                esc = True
            else:
                out.append(byte)
        frames.append(bytes(out))
    return frames, rest


conn = None                      # connessione TCP attiva verso QLab
conn_lock = threading.Lock()
lock = threading.Lock()
order = []   # uniqueIDs of the active cues, in the order received
cues = {}    # uniqueID -> dict with listName, number, actionElapsed, duration
cue_ts = {}  # uniqueID -> time of QLab's last answer for that cue
last_reply = 0.0
ws_id = None       # workspace whose answers are being received
ws_names = {}     # uniqueID -> nome visualizzato


def send(address, *args):
    with conn_lock:
        c = conn
    if c is None:
        return
    try:
        c.sendall(slip_encode(osc_encode(address, *args)))
    except OSError:
        try:
            c.close()  # makes the receiver exit, so it reconnects
        except OSError:
            pass


def handle_packet(buf):
    global last_reply, ws_id
    try:
        address, args = osc_decode(buf)
        if not args:
            return
        reply = json.loads(args[0])
    except Exception:
        return
    last_reply = time.time()
    data = reply.get("data")
    with lock:
        if reply.get("workspace_id"):
            ws_id = reply["workspace_id"]
        if address.endswith("/workspaces") and isinstance(data, list):
            ws_names.clear()
            for w in data:
                if isinstance(w, dict) and w.get("uniqueID"):
                    ws_names[w["uniqueID"]] = w.get("displayName") or ""
        elif address.endswith("/runningCues") and isinstance(data, list):
            ids = [c["uniqueID"] for c in data if "uniqueID" in c]
            order[:] = ids
            for uid in list(cues):
                if uid not in ids:
                    del cues[uid]
        elif "/cue_id/" in address and address.endswith("/valuesForKeys"):
            uid = address.split("/cue_id/")[1].split("/")[0]
            if uid in order and isinstance(data, dict):
                cues[uid] = data
                cue_ts[uid] = time.time()


def receiver():
    """Keeps the TCP connection with QLab open (and reopens it if it drops)."""
    global conn
    while True:
        try:
            c = socket.create_connection((QLAB_HOST, QLAB_PORT), timeout=3)
            c.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            c.settimeout(5)
        except OSError:
            time.sleep(2)
            continue
        with conn_lock:
            conn = c
        if PASSCODE:
            send("/connect", PASSCODE)
        send("/updates", 0)  # no push needed, we poll (once per connection)
        send("/workspaces")  # workspace name right away, without waiting for the next round
        buf = b""
        try:
            while True:
                chunk = c.recv(65536)
                if not chunk:
                    break
                frames, buf = slip_frames(buf + chunk)
                for f in frames:
                    handle_packet(f)
        except OSError:
            pass
        finally:
            with conn_lock:
                conn = None
            try:
                c.close()
            except OSError:
                pass
            with lock:
                order.clear()
                cues.clear()
        time.sleep(1)


def poller():
    keys = json.dumps(["listName", "number", "actionElapsed", "duration", "percentActionElapsed", "infiniteLoop", "playCount", "isPaused", "preWait", "preWaitElapsed", "currentDuration"])
    n = 0
    while True:
        if n % max(1, round(5 / POLL_SECONDS)) == 0:  # every ~5 seconds: names of the open workspaces
            send("/workspaces")
        n += 1
        send("/runningCues")
        with lock:
            ids = list(order)
        for uid in ids:
            send(f"/cue_id/{uid}/valuesForKeys", keys)
        # with no active cues QLab is queried less often (times are always read from QLab, so accuracy does not change)
        time.sleep(POLL_SECONDS if ids else max(POLL_SECONDS, 0.5))


ENV = dict(os.environ, LC_ALL="C", LANG="C")  # numbers with a decimal point, independent of the language
NCPU = os.cpu_count() or 1
stats = {"cpu": None, "ram": None, "used": None, "total": None, "pressure": None, "swap": None, "cores": None, "core_types": None, "ncores": os.cpu_count() or 1, "core_label": "",
         "apps": [], "apps_err": None, "sys_err": None,
         "temp": None, "batt": None, "thr": None, "disk": None, "dsk": None}


def run(cmd, timeout=10):
    return subprocess.check_output(cmd, text=True, env=ENV, timeout=timeout)


def mem_stats_fork():
    """Like Activity Monitor: used memory = app + wired + compressed (GB)."""
    total = int(run(["sysctl", "-n", "hw.memsize"]))
    out = run(["vm_stat"])
    page = int(re.search(r"page size of (\d+) bytes", out).group(1))

    def pages(label):
        return int(re.search(label + r":\s+(\d+)", out).group(1))

    used = (pages("Anonymous pages") - pages("Pages purgeable")
            + pages("Pages wired down") + pages("Pages occupied by compressor")) * page
    return used / 1024 ** 3, total / 1024 ** 3


def mem_pressure_fork():
    """Memory pressure as in Activity Monitor: 1 = normal (green), 2 = warning (yellow), 4 = critical (red)."""
    return int(run(["sysctl", "-n", "kern.memorystatus_vm_pressure_level"]).strip())


def swap_used_gb_fork():
    """Swap in uso (GB) da `sysctl vm.swapusage`."""
    out = run(["sysctl", "-n", "vm.swapusage"])
    m = re.search(r"used\s*=\s*([\d.,]+)\s*([KMGT])", out)
    if not m:
        return 0.0
    return float(m.group(1).replace(",", ".")) * {"K": 1 / 1048576, "M": 1 / 1024, "G": 1, "T": 1024}[m.group(2)]



# ---- Native readings (without running commands): memory, pressure, swap. If the result does not match that of the
# classic commands (checked the first time) it falls back to the commands automatically. ----
_nat = {}
_memsize = [None]


def _sysctl_bytes(name, size=8):
    lib = _mach()
    if not hasattr(lib, "_sc_ready"):
        lib.sysctlbyname.restype = ctypes.c_int
        lib.sysctlbyname.argtypes = [ctypes.c_char_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_size_t), ctypes.c_void_p, ctypes.c_size_t]
        lib.host_statistics64.restype = ctypes.c_int
        lib.host_statistics64.argtypes = [ctypes.c_uint, ctypes.c_int, ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint)]
        lib._sc_ready = True
    buf = ctypes.create_string_buffer(size)
    ln = ctypes.c_size_t(size)
    if lib.sysctlbyname(name.encode(), buf, ctypes.byref(ln), None, 0) != 0:
        raise OSError("sysctl " + name)
    return buf.raw[:ln.value]


def _mem_native():
    lib = _mach()
    if _memsize[0] is None:
        _memsize[0] = int.from_bytes(_sysctl_bytes("hw.memsize", 8), "little")
    page = int.from_bytes(_sysctl_bytes("hw.pagesize", 8), "little")
    words = (ctypes.c_uint32 * 64)()
    cnt = ctypes.c_uint(38)    # HOST_VM_INFO64_COUNT
    if lib.host_statistics64(lib.host_port, 4, words, ctypes.byref(cnt)) != 0 or cnt.value < 37:
        raise OSError("host_statistics64")
    wired, purgeable, compressor, internal = words[3], words[23], words[33], words[36]
    used = (internal - purgeable + wired + compressor) * page
    return used / 1024 ** 3, _memsize[0] / 1024 ** 3


def _pressure_native():
    return int.from_bytes(_sysctl_bytes("kern.memorystatus_vm_pressure_level", 4), "little")


def _swap_native():
    raw = _sysctl_bytes("vm.swapusage", 32)
    return int.from_bytes(raw[16:24], "little") / 1024 ** 3


def _checked(name, native, fork, same):
    if sys.platform != "darwin" or _nat.get(name) is False:
        return fork()
    try:
        v = native()
    except Exception:
        _nat[name] = False
        return fork()
    if _nat.get(name) is None:
        f = fork()
        if not same(v, f):
            _nat[name] = False
            return f
        _nat[name] = True
    return v


def mem_stats():
    return _checked("mem", _mem_native, mem_stats_fork, lambda a, b: abs(a[0] - b[0]) < max(0.5, b[0] * 0.05) and abs(a[1] - b[1]) < 0.01)


def mem_pressure():
    return _checked("press", _pressure_native, mem_pressure_fork, lambda a, b: a == b)


def swap_used_gb():
    return _checked("swap", _swap_native, swap_used_gb_fork, lambda a, b: abs(a - b) < max(0.1, b * 0.05))


def cpu_percent():
    """Total CPU usage (user + system) from the second top sample."""
    out = run(["top", "-l", "2", "-s", "1", "-n", "0"], timeout=20)
    idle = re.findall(r"CPU usage:.*?([\d.]+)% idle", out)
    return round(100 - float(idle[-1]), 1)


# --- CPU per single core ---
# On macOS the time counters of each core are read directly from the system (no command
# esterno da lanciare): utente, sistema, inattivo, nice. L'uso = (utente+sistema+nice) / totale,
# the same definition as Activity Monitor's "CPU Load".
_mach_lib = None


def _mach():
    global _mach_lib
    if _mach_lib is None:
        lib = ctypes.CDLL("/usr/lib/libSystem.B.dylib")
        lib.mach_host_self.restype = ctypes.c_uint
        lib.mach_host_self.argtypes = []
        lib.host_processor_info.restype = ctypes.c_int
        lib.host_processor_info.argtypes = [ctypes.c_uint, ctypes.c_int, ctypes.POINTER(ctypes.c_uint),
                                            ctypes.POINTER(ctypes.POINTER(ctypes.c_uint)),
                                            ctypes.POINTER(ctypes.c_uint)]
        lib.vm_deallocate.restype = ctypes.c_int
        lib.vm_deallocate.argtypes = [ctypes.c_uint, ctypes.c_size_t, ctypes.c_size_t]
        lib.host_port = lib.mach_host_self()
        _mach_lib = lib
    return _mach_lib


def cpu_ticks_mac():
    lib = _mach()
    ncpu, cnt = ctypes.c_uint(0), ctypes.c_uint(0)
    info = ctypes.POINTER(ctypes.c_uint)()
    kr = lib.host_processor_info(lib.host_port, 2, ctypes.pointer(ncpu), ctypes.pointer(info),
                                 ctypes.pointer(cnt))   # 2 = PROCESSOR_CPU_LOAD_INFO
    if kr != 0:
        raise OSError("host_processor_info: errore %s" % kr)
    ticks = [tuple(info[i * 4 + j] for j in range(4)) for i in range(ncpu.value)]
    try:  # free the memory returned by the system
        try:
            task = ctypes.c_uint.in_dll(lib, "mach_task_self_").value
        except Exception:
            lib.mach_task_self.restype = ctypes.c_uint
            task = lib.mach_task_self()
        lib.vm_deallocate(task, ctypes.cast(info, ctypes.c_void_p).value, cnt.value * 4)
    except Exception:
        pass
    return ticks


def cpu_ticks_linux():  # only for tests on Linux
    out = []
    with open("/proc/stat") as f:
        for line in f:
            if line.startswith("cpu") and line[3:4].isdigit():
                p = line.split()
                out.append((int(p[1]), int(p[3]), int(p[4]) + (int(p[5]) if len(p) > 5 else 0), int(p[2])))
    return out


def cpu_ticks():
    return cpu_ticks_mac() if sys.platform == "darwin" else cpu_ticks_linux()


def cpu_per_core():
    """Usage (%) of each core over a 1-second window. Returns the list, one value per core."""
    a = cpu_ticks()
    time.sleep(1)
    b = cpu_ticks()
    res = []
    for x, y in zip(a, b):
        d = [(y[i] - x[i]) & 0xFFFFFFFF for i in range(4)]   # the counters are 32-bit
        tot = sum(d)
        res.append(round((d[0] + d[1] + d[3]) / tot * 100, 1) if tot > 0 else 0.0)
    if not res:
        raise OSError("no core read")
    return res


def core_label():
    """For example '8P+2E' (Apple Silicon: performance + efficiency cores) or '6C/12T' (Intel with hyperthreading)."""
    try:
        p = int(run(["sysctl", "-n", "hw.perflevel0.logicalcpu"]))
        e = int(run(["sysctl", "-n", "hw.perflevel1.logicalcpu"]))
        return f"{p}P+{e}E" if e else f"{p}P"
    except Exception:
        pass
    try:
        phys = int(run(["sysctl", "-n", "hw.physicalcpu"]))
        logi = int(run(["sysctl", "-n", "hw.logicalcpu"]))
        return f"{phys}C/{logi}T" if phys != logi else ""
    except Exception:
        return ""


def _types_ioreg(n):
    """Type of each core ('P' or 'E') read from the device tree (cluster-type of cpu0, cpu1...). None if it cannot be read."""
    try:
        out = run(["ioreg", "-r", "-c", "IOPlatformDevice", "-l", "-w", "0"], timeout=25)
    except Exception:
        return None
    found, cur = {}, None
    for line in out.splitlines():
        m = re.search(r"\+-o cpu(\d+)@", line)
        if m:
            cur = int(m.group(1))
            continue
        if "+-o " in line:
            cur = None
            continue
        if cur is not None and "cluster-type" in line:
            m = re.search(r'"cluster-type" = <(?:"([A-Za-z])"|([0-9a-fA-F]{2}))', line)
            if m:
                k = (m.group(1) or {"45": "E", "50": "P"}.get(m.group(2), "?")).upper()
                found[cur] = k
    if len(found) == n and all(i in found for i in range(n)):
        return [found[i] for i in range(n)]
    return None


def core_types(n):
    """['E','E','P',...] with n entries (Apple Silicon: efficiency and performance cores), None on Macs without this split."""
    try:
        p = int(run(["sysctl", "-n", "hw.perflevel0.logicalcpu"]))
        e = int(run(["sysctl", "-n", "hw.perflevel1.logicalcpu"]))
    except Exception:
        return None
    if p <= 0 or e <= 0 or p + e != n:
        return None
    t = _types_ioreg(n)
    if t and t.count("P") == p and t.count("E") == e:
        return t
    return ["E"] * e + ["P"] * p     # on Apple Silicon the efficiency cores have the lowest numbers


_warned = set()


def warn_once(key, e):
    if key not in _warned:
        _warned.add(key)
        print(f"sys_stats {key}:", e)


def sys_stats():
    stats["core_label"] = core_label()
    while True:
        try:
            used, total = mem_stats()
            stats.update(used=round(used, 1), total=round(total, 1),
                         ram=round(used / total * 100, 1))
            stats["sys_err"] = None
        except Exception as e:
            stats["sys_err"] = "ram: " + repr(e)[:100]
            print("sys_stats ram:", e)
        try:
            stats["pressure"] = mem_pressure()
        except Exception as e:
            stats["pressure"] = None
            print("sys_stats pressione:", e)
        try:
            stats["swap"] = round(swap_used_gb(), 2)
        except Exception as e:
            stats["swap"] = None
            print("sys_stats swap:", e)
        try:
            per = cpu_per_core()
            if not stats.get("types_done"):
                stats["types_done"] = True
                try:
                    stats["core_types"] = core_types(len(per))
                except Exception as e:
                    warn_once("core_types", e)
            stats["cores"] = per
            stats["ncores"] = len(per)
            stats["cpu"] = round(sum(per) / len(per), 1)
        except Exception as e:
            stats["cores"] = None
            warn_once("core", e)
            try:  # fallback: total usage from top, without the per-core detail
                stats["cpu"] = cpu_percent()
            except Exception as e2:
                stats["sys_err"] = "cpu: " + repr(e2)[:100]
                warn_once("cpu", e2)
        time.sleep(SYS_SECONDS)


APP_NAME = "The Endurance"


def app_name(path):
    """Groups processes by app: 'Google Chrome.app/.../Helper' -> 'Google Chrome'."""
    for part in path.split("/"):
        if part.endswith(".app"):
            return APP_NAME if part == "The_Endurance.app" else part[:-4]
    return os.path.basename(path)


def cpu_seconds(t):
    """CPU time from ps ('1:02.34', '1:02:03.45', '2-01:02:03') in seconds."""
    days = 0
    if "-" in t:
        d, t = t.split("-", 1)
        days = int(d)
    secs = 0.0
    for part in t.split(":"):
        secs = secs * 60 + float(part.replace(",", "."))
    return days * 86400 + secs


def top_apps(n=5):
    """The first n apps with CPU above 0%, sorted by CPU, aggregating the processes.
    CPU = % of one core, as in Activity Monitor (can exceed 100)."""
    try:
        total_gb = int(run(["sysctl", "-n", "hw.memsize"])) / 1024 ** 3
    except Exception:
        total_gb = 16.0
    prev, prev_t = {}, None
    while True:
        try:
            out = run(["ps", "-axo", "pid=,time=,rss=,comm="])
            now = time.time()
            dt = (now - prev_t) if prev_t else 0
            cur, agg, meta = {}, {}, {}
            for line in out.splitlines():
                parts = line.split(None, 3)
                if len(parts) < 4:
                    continue
                try:
                    pid = int(parts[0])
                    t = cpu_seconds(parts[1])
                    gb = int(parts[2]) / 1048576
                except ValueError:
                    continue
                cur[pid] = t
                pct = 0.0
                if dt > 0 and pid in prev and t >= prev[pid]:
                    pct = (t - prev[pid]) / dt * 100
                comm = parts[3].strip()
                name = APP_NAME if pid == MY_PID else app_name(comm)
                a = agg.setdefault(name, [0.0, 0.0])
                a[0] += pct
                a[1] += gb
                mt = meta.setdefault(name, [".app/" in comm, os.path.basename(comm), set()])
                mt[2].add(pid)
            if APP_NAME in agg:   # node at the top and row in the list: same measure (all The Endurance processes)
                selfinfo["cpu"] = round(agg[APP_NAME][0], 1)
                selfinfo["mb"] = round(agg[APP_NAME][1] * 1024, 1)
            prev, prev_t = cur, now
            keyc = (config.get("key_app") or "").strip()
            active = [(k, v) for k, v in agg.items() if round(v[0], 1) > 0
                      and not (keyc and k != APP_NAME and key_match(k, keyc))          # the key app has its own row: not repeated
                      and not (config.get("lp_extra") and k != APP_NAME and key_match(k, "Live Professor"))
                      and not (k in APP_LABELS and v[0] < APP_LABELS[k][1])]            # system audio services: only if they are really working
            ranked = sorted(active, key=lambda kv: kv[1][0], reverse=True)
            stats["apps"] = [{"name": APP_LABELS[k][0] if k in APP_LABELS else k, "cpu": round(v[0], 1), "gb": round(v[1], 2)}
                             for k, v in ranked[:n]]
            stats["apps_err"] = None if agg else "no process read"
            key_update(agg, meta, now)
        except Exception as e:
            stats["apps_err"] = repr(e)[:120]
            print("top_apps:", e)
        time.sleep(min(APPS_SECONDS, 3.0) if (config.get("key_app") or "").strip() else APPS_SECONDS)


MY_PID = os.getpid()
selfinfo = {"cpu": None, "mb": None}   # usage of The Endurance itself (CPU % of one core, RAM in MB)


net = []   # [{"name": "Wi-Fi", "ip": "192.168.1.20"}, ...]


_svc_cache = {"t": 0.0, "map": {}}
_svc_lock = threading.Lock()


def net_services(ttl=10):
    """Network services as shown in System Settings > Network: device -> service name,
    configuration (DHCP / manual) and gateway. Recomputed at most every 10 seconds."""
    with _svc_lock:
        if time.time() - _svc_cache["t"] < ttl and _svc_cache["map"]:
            return _svc_cache["map"]
        m = {}
        try:
            lines = run(["networksetup", "-listnetworkserviceorder"], timeout=5).splitlines()
        except Exception:
            lines = []
        order = 0
        for i, ln in enumerate(lines):
            mm = re.match(r"^\((\*|\d+)\)\s+(.+)$", ln.strip())
            if not mm or i + 1 >= len(lines):
                continue
            h = re.search(r"Hardware Port:\s*(.*?),\s*Device:\s*([^)\s]*)", lines[i + 1])
            if not h or not h.group(2):
                continue
            m[h.group(2)] = {"service": mm.group(2).strip(), "hw": h.group(1).strip(), "enabled": mm.group(1) != "*",
                             "order": order, "mode": "", "router": ""}
            order += 1
        for dev, v in m.items():
            try:
                info = run(["networksetup", "-getinfo", v["service"]], timeout=4)
                first = (info.strip().splitlines() or [""])[0].lower()
                v["mode"] = ("MANUAL" if first.startswith("manual") else "DHCP" if first.startswith("dhcp")
                             else "BOOTP" if first.startswith("bootp") else "")
                r = re.search(r"^Router:\s*(\d+\.\d+\.\d+\.\d+)", info, re.M)
                v["router"] = r.group(1) if r else ""
            except Exception:
                pass
            if not v["router"]:
                try:
                    v["router"] = run(["ipconfig", "getoption", dev, "router"], timeout=3).strip()
                except Exception:
                    pass
        _svc_cache.update(t=time.time(), map=m)
        return m


_hw_cache = {"t": 0.0, "out": ""}
_net_sig = [None]


# ---- NETWORK INTERFACES: which ports The Endurance acts on (user's choice, flags in the "Network interfaces" tab) ----
# The choice is stored in a text file "device=1|0" (also written by the app window, even with the monitor stopped).
# Choice never made: all ports are used (and the window does not start the monitor before the choice).
# Choice made: a port that is not ticked, or that appears later, receives NOTHING from The Endurance (no scans,
# pings, pull, autosave) and does not even have a server listening.
net_ports = []         # all ports: {"dev", "name", "hw", "ip", "ll" (169.254), "prefix", "kind"}
_pref_cache = {}
_netsel = {"mt": None, "sel": None}
_netsel_lock = threading.Lock()


def netsel_path():
    return os.path.join(DEFCON_DIR, "net-interfaces")


def netsel_read():
    """None if the choice has never been made; otherwise {device: True/False}."""
    try:
        mt = os.stat(netsel_path()).st_mtime_ns
    except OSError:
        with _netsel_lock:
            _netsel.update(mt=None, sel=None)
        return None
    with _netsel_lock:
        if mt != _netsel["mt"] or _netsel["sel"] is None:
            sel = {}
            try:
                with open(netsel_path(), encoding="utf-8") as f:
                    for ln in f:
                        m = re.fullmatch(r"([a-z]+[0-9]+)=([01])", ln.strip())
                        if m:
                            sel[m.group(1)] = m.group(2) == "1"
            except OSError:
                return _netsel["sel"]
            _netsel.update(mt=mt, sel=sel)
        return _netsel["sel"]


def net_monitored(dev):
    sel = netsel_read()
    if sel is None or str(dev).startswith("lo"):
        return True
    return bool(sel.get(dev, False))


def netsel_write(sel):
    os.makedirs(DEFCON_DIR, exist_ok=True)
    tmp = netsel_path() + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write("".join("%s=%d\n" % (d, 1 if v else 0) for d, v in sorted(sel.items())))
    os.replace(tmp, netsel_path())
    with _netsel_lock:
        _netsel.update(mt=None, sel=None)


def netsel_set(dev, on):
    if not re.fullmatch(r"[a-z]+[0-9]+", str(dev or "")):
        return False
    sel = netsel_read()
    sel = {p["dev"]: True for p in net_ports} if sel is None else dict(sel)
    sel[dev] = bool(on)
    netsel_write(sel)
    return True


def netsel_confirm():
    sel = netsel_read()
    netsel_write({p["dev"]: True for p in net_ports} if sel is None else sel)
    return True


def _port_net(p):
    try:
        if p.get("ip") and p.get("prefix"):
            return ipaddress.ip_network("%s/%d" % (p["ip"], p["prefix"]), strict=False)
    except ValueError:
        pass
    return None


def ip_excluded(ip):
    """True if the address is on a port the user has excluded (The Endurance then sends nothing to it)."""
    sel = netsel_read()
    if sel is None:
        return False
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if a.is_loopback:
        return False
    ports = list(net_ports)
    if not ports:             # the ports have not been read yet: with a choice made we stay cautious (no traffic)
        return True
    if a.is_link_local:       # 169.254.x.x: uncertain port, we stay cautious if a link-local port is excluded
        return any(p.get("ll") and not sel.get(p["dev"], False) for p in ports)
    best, bl = None, -1
    for p in ports:
        n = _port_net(p)
        if n is not None and a in n and n.prefixlen > bl:
            best, bl = p["dev"], n.prefixlen
    return best is not None and not sel.get(best, False)


def local_blocked(addr):
    """True if the local address (a connection arrived on) belongs to an excluded port."""
    sel = netsel_read()
    if sel is None or not addr or addr.startswith("127."):
        return False
    return any(addr in (p.get("ip"), p.get("ll")) and not sel.get(p["dev"], False) for p in list(net_ports))


def ifaces_view(local=False):
    sel = netsel_read()
    rows = []
    for p in list(net_ports):
        on = True if sel is None else bool(sel.get(p["dev"], False))
        rows.append({"dev": p["dev"], "name": p["name"], "hw": p["hw"], "ip": p["ip"] or p["ll"], "ll": bool(p["ll"]),
                     "kind": p["kind"], "active": bool(p["ip"] or p["ll"]), "on": on, "new": sel is not None and p["dev"] not in sel})
    rows.sort(key=lambda r: (not r["active"],))
    return {"ifaces": rows, "configured": sel is not None, "local": local, "port": HTTP_PORT, "now": time.time(),
            "on": sum(1 for r in rows if r["on"] and r["active"]), "active": sum(1 for r in rows if r["active"])}


def netsel_summary():
    v = ifaces_view()
    return {"configured": v["configured"], "on": v["on"], "active": v["active"]}


def net_addrs(_retry=True):
    """IPv4 addresses of the active interfaces the user left monitored (Wi-Fi, Ethernet/LAN, USB adapters...).
    All ports, even the excluded ones, stay in net_ports for the Network interfaces tab."""
    found, ports = [], []
    try:
        if time.time() - _hw_cache["t"] >= 300 or not _hw_cache["out"]:    # the list of hardware ports rarely changes
            _hw_cache.update(t=time.time(), out=run(["networksetup", "-listallhardwareports"]))
        out = _hw_cache["out"]
        svc = net_services(120)
        for block in out.split("Hardware Port:")[1:]:
            lines = block.strip().splitlines()
            name = lines[0].strip()
            dev = next((l.split(":", 1)[1].strip() for l in lines if l.startswith("Device:")), "")
            if not dev:
                continue
            ip = ""
            try:
                ip = run(["ipconfig", "getifaddr", dev], timeout=3).strip()
            except Exception:
                pass
            ll = ip if ip.startswith("169.254.") else ""
            ip = "" if ll else ip
            sv = svc.get(dev) or {}
            lw = name.lower()
            kind = "Wi-Fi" if ("wi-fi" in lw or "wifi" in lw or "airport" in lw) else "Ethernet"
            pr = None
            if ip:
                pr = _pref_cache.get((dev, ip))
                if pr is None:
                    pr = _pref_cache[(dev, ip)] = iface_prefix(dev)
            ports.append({"dev": dev, "name": sv.get("service") or name, "hw": name, "ip": ip, "ll": ll, "prefix": pr, "kind": kind})
            if ip:
                found.append({"name": sv.get("service") or name, "ip": ip, "dev": dev, "kind": kind,
                              "mode": sv.get("mode", ""), "router": sv.get("router", "")})
    except Exception:
        pass
    sig = tuple(sorted((f.get("dev", ""), f["ip"]) for f in found))
    if sig != _net_sig[0]:
        first, _net_sig[0] = _net_sig[0] is None, sig
        if _retry and not first:     # addresses changed: ports and services are re-read just once
            _hw_cache["t"] = 0.0
            _svc_cache["t"] = 0.0
            return net_addrs(False)
    if ports:
        net_ports[:] = ports
    found = [f for f in found if net_monitored(f["dev"])]
    if not found and not ports:  # fallback (not macOS): address of the default interface
        ip = local_ip()
        if ip != "IP-DEL-MAC":
            found.append({"name": "Rete", "ip": ip})
    return found


def net_loop():
    while True:
        try:
            net[:] = net_addrs()
        except Exception as e:
            print("net_loop:", e)
        time.sleep(30 if show_mode() else 10)


# --- Other Macs with QLab on the same network ---
# We look for who has port 53000 (QLab OSC) open on the local network this Mac is connected to
# (at most one /24 block per interface, private networks only) and ask for /workspaces, which QLab
# accepts without a passcode: it returns the names of the workspaces open on that Mac.
# System resources (CPU, RAM...) are ALWAYS and only those of this Mac.
peers = {}           # ip -> {"ip", "host", "workspaces": [nomi], "seen": t}
peers_lock = threading.Lock()
_name_cache = {}     # ip -> (name, when)
_host_name = None


def host_name():
    """Name of this Mac (what you see in Settings > General > About)."""
    global _host_name
    if _host_name is None:
        for cmd in (["scutil", "--get", "ComputerName"], ["scutil", "--get", "LocalHostName"], ["hostname", "-s"]):
            try:
                n = run(cmd, timeout=3).strip()
            except Exception:
                continue
            if n:
                _host_name = n
                break
        if not _host_name:
            _host_name = socket.gethostname().split(".")[0] or "HOST"
    return _host_name


def is_scannable(ip):
    a = ipaddress.ip_address(ip)
    return a.version == 4 and a.is_private and not a.is_loopback and not a.is_link_local


def iface_prefix(dev):
    try:
        mask = run(["ipconfig", "getoption", dev, "subnet_mask"], timeout=3).strip()
        return ipaddress.IPv4Network("0.0.0.0/" + mask).prefixlen
    except Exception:
        return 24


def scan_targets(addrs):
    """Addresses to check: the subnet of each interface (at most /24), except our own."""
    own = {a["ip"] for a in addrs}
    out = {}
    for a in addrs:
        try:
            if not is_scannable(a["ip"]):
                continue
            prefix = max(24, iface_prefix(a["dev"]) if a.get("dev") else 24)
            for h in ipaddress.ip_network(f"{a['ip']}/{prefix}", strict=False).hosts():
                if str(h) not in own:
                    out[str(h)] = True
        except ValueError:
            continue
    return list(out)


def extra_peers():
    out = []
    for raw in os.environ.get("DP_EXTRA", "").replace(";", ",").split(",") + list(EXTRA_PEERS):
        try:
            out.append(str(ipaddress.IPv4Address(raw.strip())))
        except ValueError:
            pass
    return list(dict.fromkeys(out))


def port_open(ip, port=QLAB_PORT, timeout=0.4):
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


def query_workspaces(ip, port=QLAB_PORT, timeout=2.0):
    """Names of the workspaces open on another Mac (None if it does not answer like QLab)."""
    c = socket.create_connection((ip, port), timeout=timeout)
    try:
        c.settimeout(0.5)
        c.sendall(slip_encode(osc_encode("/workspaces")))
        buf, deadline = b"", time.time() + timeout
        while time.time() < deadline:
            try:
                chunk = c.recv(65536)
            except socket.timeout:
                continue
            if not chunk:
                break
            frames, buf = slip_frames(buf + chunk)
            for f in frames:
                try:
                    address, args = osc_decode(f)
                    data = json.loads(args[0]).get("data")
                except Exception:
                    continue
                if address.endswith("/workspaces") and isinstance(data, list):
                    return [w.get("displayName") or "(senza nome)" for w in data if isinstance(w, dict)]
        return None
    finally:
        c.close()


def mac_name(ip):
    """Name of the Mac (from DNS/Bonjour), if it can be found out within 1.5 seconds."""
    name, when = _name_cache.get(ip, ("", 0))
    if name or time.time() - when < 300:
        return name
    box = []

    def work():
        try:
            box.append(socket.gethostbyaddr(ip)[0])
        except Exception:
            pass

    t = threading.Thread(target=work, daemon=True)
    t.start()
    t.join(1.5)
    name = box[0].split(".")[0].replace("-", " ").strip() if box else ""
    _name_cache[ip] = (name, time.time())
    return name


def peers_loop():
    time.sleep(2)
    last_sweep = 0.0
    while True:
        t0 = time.time()
        try:
            addrs = list(net) or net_addrs()
            own = {a["ip"] for a in addrs}
            found = []
            if t0 - last_sweep >= max(60.0, PEERS_SECONDS * 4) and not show_mode():      # full network scan: about once a minute
                last_sweep = t0
                targets = scan_targets(addrs)
                if targets:
                    with ThreadPoolExecutor(max_workers=32) as ex:
                        found = [ip for ip, ok in zip(targets, ex.map(port_open, targets)) if ok]
            else:                                                    # in the other rounds only the Macs already found are queried again
                with peers_lock:
                    found = list(peers)
            for e in extra_peers():
                if e not in found and e not in own:
                    found.append(e)
            found = [ip for ip in found if not ip_excluded(ip)]      # porte escluse dall'utente: niente traffico
            for ip in found:
                try:
                    names = query_workspaces(ip)
                except OSError:
                    names = None
                if names is None:
                    continue
                with peers_lock:
                    peers[ip] = {"ip": ip, "host": mac_name(ip), "workspaces": names, "seen": time.time()}
            cutoff = time.time() - max(60.0, PEERS_SECONDS * 4) * 2 - 5   # disappears after ~2 scans without an answer
            with peers_lock:
                for ip in [k for k, v in peers.items() if v["seen"] < cutoff]:
                    del peers[ip]
        except Exception as e:
            print("peers_loop:", e)
        time.sleep(max(1.0, PEERS_SECONDS - (time.time() - t0)))


# ---- Autosave of the QLab workspaces ("save" command, like Cmd+S) on all Macs with QLab on the network ----
AUTOSAVE_CFG = os.path.join(os.path.expanduser("~"), "Library", "Application Support", "The Endurance", "autosave")
autosave = {"enabled": False, "minutes": 5.0, "last": None, "next": None, "ok": 0, "total": 0, "err": "", "names": []}
autosave_lock = threading.Lock()


def autosave_load():
    """Only remembers the interval chosen last time: the flag always restarts off."""
    try:
        with open(AUTOSAVE_CFG) as f:
            m = float(f.read().strip().split("=")[-1])
        autosave["minutes"] = min(120.0, max(1.0, m))
    except Exception:
        pass


def autosave_set(enabled, minutes):
    """When enabled, the first save is immediate, then every `minutes` minutes."""
    if enabled and show_mode():
        return
    with autosave_lock:
        autosave["minutes"] = minutes
        autosave["enabled"] = enabled
        autosave["next"] = time.time() if enabled else None
        if not enabled:
            autosave["err"] = ""
    try:
        os.makedirs(os.path.dirname(AUTOSAVE_CFG), exist_ok=True)
        with open(AUTOSAVE_CFG, "w") as f:
            f.write("MINUTES=%g\n" % minutes)
    except OSError:
        pass


def qlab_save_all(ip, timeout=4.0):
    """Sends /workspace/<id>/save to all the workspaces open on a Mac with QLab.
    Returns [(workspace name, status)]: status "ok" or the reason for the refusal. If QLab does not answer the save
    the command has been sent anyway: it is considered saved."""
    c = socket.create_connection((ip, QLAB_PORT), timeout=2.0)
    try:
        c.settimeout(0.4)
        c.sendall(slip_encode(osc_encode("/workspaces")))
        buf, sent, names, results = b"", False, {}, {}
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                chunk = c.recv(65536)
            except socket.timeout:
                chunk = None
            if chunk == b"":
                break
            if chunk:
                frames, buf = slip_frames(buf + chunk)
                for f in frames:
                    try:
                        address, args = osc_decode(f)
                    except Exception:
                        continue
                    try:
                        data = json.loads(args[0]) if args else {}
                    except Exception:
                        data = {}
                    if address.endswith("/workspaces") and not sent:
                        lst = data.get("data") if isinstance(data, dict) else None
                        for w in (lst or []):
                            if isinstance(w, dict) and w.get("uniqueID"):
                                names[w["uniqueID"]] = w.get("displayName") or "(untitled)"
                        if not names:
                            return []
                        for i in names:
                            c.sendall(slip_encode(osc_encode("/workspace/%s/save" % i)))
                        sent = True
                    elif address.endswith("/save"):
                        m = re.search(r"/workspace/([^/]+)/save", address)
                        if m and m.group(1) in names:
                            st = data.get("status") if isinstance(data, dict) else None
                            results[m.group(1)] = str(st) if st else "ok"
            if sent and len(results) >= len(names):
                break
        return [(names[i], results.get(i, "ok")) for i in names]
    finally:
        c.close()


def autosave_round():
    with peers_lock:
        remote = [(ip, v.get("host") or ip) for ip, v in peers.items() if not ip_excluded(ip)]
    targets = [("127.0.0.1", host_name() or "this Mac")] + remote
    names, errs, total = [], [], 0

    def work(t):
        try:
            return t, qlab_save_all(t[0]), None
        except OSError as e:
            return t, None, e

    with ThreadPoolExecutor(max_workers=8) as ex:
        for t, r, e in ex.map(work, targets):
            if e is not None:
                if t[0] != "127.0.0.1":     # QLab not open on this Mac: not an error
                    errs.append("%s: not reachable" % t[1])
                continue
            for name, st in r:
                total += 1
                if st == "ok":
                    names.append(name)
                else:
                    errs.append("%s: %s" % (name, st))
    with autosave_lock:
        autosave["last"] = time.time()
        autosave["ok"], autosave["total"] = len(names), total
        autosave["names"] = list(dict.fromkeys(names))[:12]
        autosave["err"] = "; ".join(errs)[:200]
        if autosave["enabled"]:
            autosave["next"] = time.time() + autosave["minutes"] * 60


def autosave_loop():
    while True:
        time.sleep(1.0)
        try:
            with autosave_lock:
                due = autosave["enabled"] and autosave["next"] is not None and time.time() >= autosave["next"]
                if due:
                    autosave["next"] = time.time() + 3600   # avoids a second round while this one is running
            if due:
                autosave_round()
        except Exception as e:
            print("autosave:", e)


# ---- Mac environment: CPU temperature, battery, thermal limit, disk space ----
def read_batt():
    """{'pct': 87, 'src': 'AC'|'BATT', 'state': 'charging'} or None if the Mac has no battery."""
    out = run(["pmset", "-g", "batt"], timeout=5)
    m = re.search(r"(\d+)%", out)
    if not m:
        return None
    st = re.search(r"%;\s*([A-Za-z ]+?);", out)
    return {"pct": int(m.group(1)), "src": "BATT" if "Battery Power" in out else "AC", "state": st.group(1).strip() if st else ""}


def read_therm():
    """Thermal limit imposed by macOS in % (100 = no limit), None if not reported."""
    out = run(["pmset", "-g", "therm"], timeout=5)
    vals = [int(x) for x in re.findall(r"CPU_(?:Speed|Scheduler)_Limit\s*=\s*(\d+)", out)]
    return min(vals) if vals else None


# ---- DISK: free space, read/write, latency, health and external disks (with the key app's contribution) ----
DISK_FREE_Y, DISK_FREE_R = 20.0, 10.0      # GB liberi: giallo / rosso
DISK_PCT_Y, DISK_PCT_R = 10.0, 5.0         # % libero: giallo / rosso
DISK_LAT = {True: (10.0, 40.0), False: (40.0, 100.0)}     # latenza media in ms (SSD / disco meccanico): giallo / rosso
DISK_MIN_IOPS = 3.0                        # below this activity the latency does not matter
DISK_EVERY, DISK_EVERY_WATCH = 15.0, 5.0   # seconds between two readings (5 only while the Disk tab is open)
disk_lock = threading.Lock()
disk = {"vols": [], "sys": None, "key": None, "t": 0.0, "watch": 0.0}
disk_prev = {}
disk_kprev = [None]
key_pids = []
qvols = set()                              # volumi su cui l'app chiave ha avuto file aperti


def disk_free_lv(free, tot):
    if free is None:
        return 0
    pct = free / tot * 100 if tot else 100.0
    if free < DISK_FREE_R or pct < DISK_PCT_R:
        return 3
    if free < DISK_FREE_Y or pct < DISK_PCT_Y:
        return 2
    return 1


def disk_lat_lv(ms, ssd, iops):
    if ms is None or iops is None or iops < DISK_MIN_IOPS:
        return 1
    y, r = DISK_LAT[bool(ssd)]
    return 3 if ms >= r else 2 if ms >= y else 1


def disk_smart_lv(s):
    if not s:
        return 0
    s = str(s).lower()
    return 3 if "fail" in s else 1 if "verified" in s else 0


def parse_io(text):
    """ioreg counters (IOBlockStorageDriver): {physical disk: bytes, cumulative operations and times}."""
    out = {}
    for blk in re.split(r"(?m)^\+-o ", text or "")[1:]:
        m = re.search(r'"Statistics" = \{([^}]*)\}', blk)
        b = re.search(r'"BSD Name" = "(disk\d+)"', blk)
        if not m or not b:
            continue
        kv = {k: int(v) for k, v in re.findall(r'"([^"]+)"=(\d+)', m.group(1))}
        out[b.group(1)] = {"rb": kv.get("Bytes (Read)", 0), "wb": kv.get("Bytes (Write)", 0),
                           "ro": kv.get("Operations (Read)", 0), "wo": kv.get("Operations (Write)", 0),
                           "rt": kv.get("Total Time (Read)", 0), "wt": kv.get("Total Time (Write)", 0)}
    return out


def io_rates(cur, now):
    """Difference between two readings: MB/s, operations per second and average latency (ms) per physical disk."""
    res = {}
    for bsd, c in cur.items():
        p = disk_prev.get(bsd)
        disk_prev[bsd] = (now, c)
        if not p or now - p[0] < 1:
            continue
        dt, q = now - p[0], p[1]
        d = {k: c[k] - q[k] for k in c}
        if min(d.values()) < 0:
            continue
        ops = d["ro"] + d["wo"]
        res[bsd] = {"r": d["rb"] / dt / 1e6, "w": d["wb"] / dt / 1e6, "iops": ops / dt,
                    "lat": (d["rt"] + d["wt"]) / ops / 1e6 if ops else None,
                    "rl": d["rt"] / d["ro"] / 1e6 if d["ro"] else None,
                    "wl": d["wt"] / d["wo"] / 1e6 if d["wo"] else None}
    return res


def read_mounts():
    """Local volumes on disk: [(device, mount point)]. Network volumes are left out (a stuck network mount blocks statvfs)."""
    res = []
    try:
        out = run(["/sbin/mount"], timeout=5)
    except Exception:
        return res
    for ln in out.splitlines():
        m = re.match(r"(/dev/disk\S+) on (.+?) \(([^)]*)\)", ln)
        if m and (m.group(2) == "/" or m.group(2).startswith("/Volumes/")):
            res.append((m.group(1), m.group(2)))
    return res


def disk_info(mnt):
    try:
        r = subprocess.run(["diskutil", "info", "-plist", mnt], capture_output=True, timeout=8, env=ENV)
        return plistlib.loads(r.stdout)
    except Exception:
        return None


def disk_topology():
    """Volumes, physical disk of each (also for APFS), internal or external, SSD or mechanical, S.M.A.R.T. status."""
    vols = []
    for dev, mnt in read_mounts():
        i = disk_info(mnt)
        if not i or i.get("BusProtocol") == "Disk Image":
            continue
        st = i.get("APFSPhysicalStores")
        first = (st[0].get("APFSPhysicalStore") if isinstance(st[0], dict) else st[0]) if isinstance(st, list) and st else i.get("ParentWholeDisk", "")
        m = re.match(r"disk\d+", str(first or ""))
        vols.append({"mnt": mnt, "name": i.get("VolumeName") or os.path.basename(mnt) or "Macintosh HD",
                     "bsd": m.group(0) if m else "", "internal": bool(i.get("Internal")), "ssd": bool(i.get("SolidState", True)),
                     "smart": i.get("SMARTStatus") or "", "bus": i.get("BusProtocol") or ""})
    return vols


def proc_io(pid):
    """Bytes read and written to disk by a process (libproc, counters only)."""
    try:
        lib = ctypes.CDLL("/usr/lib/libSystem.B.dylib")
        buf = ctypes.create_string_buffer(256)
        if lib.proc_pid_rusage(int(pid), 2, buf) != 0:
            return None
        return struct.unpack_from("<QQ", buf.raw, 144)
    except Exception:
        return None


def key_io(now):
    """MB/s letti e scritti dall'app chiave."""
    pids = list(key_pids)
    if not pids:
        disk_kprev[0] = None
        return None
    rd = wr = 0
    for p in pids:
        v = proc_io(p)
        if v is None:
            return None
        rd, wr = rd + v[0], wr + v[1]
    prev, disk_kprev[0] = disk_kprev[0], (now, tuple(pids), rd, wr)
    if not prev or prev[1] != tuple(pids) or now - prev[0] < 1 or rd < prev[2] or wr < prev[3]:
        return None
    dt = now - prev[0]
    return {"r": (rd - prev[2]) / dt / 1e6, "w": (wr - prev[3]) / dt / 1e6}


def key_files(vols):
    """Key app files per volume (lsof, only on request and never in SHOW)."""
    pids = list(key_pids)
    if not pids:
        return {}
    try:
        r = subprocess.run(["lsof", "-nP", "-Fn", "-p", ",".join(str(p) for p in pids)], capture_output=True, text=True, timeout=4, env=ENV)
    except Exception:
        return {}
    mnts = sorted((v["mnt"] for v in vols), key=len, reverse=True)
    boot = "/" if "/" in mnts else None
    cnt = {}
    for ln in r.stdout.splitlines():
        if not ln.startswith("n/"):
            continue
        path = ln[1:]
        for m in mnts:
            if m != "/" and (path == m or path.startswith(m + "/")):
                cnt[m] = cnt.get(m, 0) + 1
                break
        else:
            if boot and path.startswith("/Users/"):
                cnt[boot] = cnt.get(boot, 0) + 1
    return cnt


def disk_build(topo, free, rates, kio, files, now):
    """Puts the data for the page together and computes the colours (1 green, 2 yellow, 3 red, 0 not available)."""
    vols, tile = [], 1
    tr = tw = 0.0
    seen = set()
    for bsd, r in rates.items():
        tr, tw = tr + r["r"], tw + r["w"]
    worst_lat, worst_iops = None, 0.0
    for v in topo:
        f = free.get(v["mnt"]) or (None, None)
        r = rates.get(v["bsd"]) or {}
        qf = files.get(v["mnt"], 0)
        if qf:
            qvols.add(v["mnt"])
        used = v["mnt"] in qvols
        flv = disk_free_lv(f[0], f[1])
        llv = disk_lat_lv(r.get("lat"), v["ssd"], r.get("iops"))
        slv = disk_smart_lv(v["smart"])
        boot = v["mnt"] == "/"
        # the overall colour counts for the startup disk and for the volumes used by the key app; the others are informational only
        if boot or used:
            tile = max(tile, flv, llv, slv)
        elif slv == 3:
            tile = 3
        if r.get("lat") is not None and r.get("iops", 0) >= DISK_MIN_IOPS and (worst_lat is None or r["lat"] > worst_lat):
            worst_lat, worst_iops = r["lat"], r["iops"]
        vols.append({"mnt": v["mnt"], "name": v["name"], "free": None if f[0] is None else round(f[0], 1),
                     "total": None if f[1] is None else round(f[1], 1), "flv": flv, "internal": v["internal"], "ssd": v["ssd"],
                     "bus": v["bus"], "smart": v["smart"], "slv": slv, "bsd": v["bsd"], "files": qf, "used": used, "boot": boot,
                     "r": None if not r else round(r["r"], 2), "w": None if not r else round(r["w"], 2),
                     "lat": None if r.get("lat") is None else round(r["lat"], 1), "iops": None if not r else round(r["iops"], 1), "llv": llv})
    key = None
    if kio is not None or key_pids:
        k = kio or {}
        tot = tr + tw
        kt = (k.get("r") or 0) + (k.get("w") or 0)
        key = {"r": None if kio is None else round(k["r"], 2), "w": None if kio is None else round(k["w"], 2),
               "share": None if (kio is None or tot < 0.1) else min(100, round(kt / tot * 100))}
    boot_f = next((v["free"] for v in vols if v["boot"]), None)
    sysd = {"lv": tile, "free": boot_f, "r": round(tr, 2), "w": round(tw, 2),
            "lat": None if worst_lat is None else round(worst_lat, 1),
            "llv": max([v["llv"] for v in vols] or [1]), "flv": next((v["flv"] for v in vols if v["boot"]), 0), "smart_bad": any(v["slv"] == 3 for v in vols)}
    return vols, sysd, key


def disk_loop():
    topo, topo_sig, topo_t = [], None, 0.0
    free, free_t, last, files_t = {}, 0.0, 0.0, 0.0
    files = {}
    while True:
        try:
            now = time.time()
            watch = now - disk["watch"] < 20
            if now - last >= (DISK_EVERY_WATCH if watch else DISK_EVERY):
                last = now
                try:
                    sig = tuple(sorted(os.listdir("/Volumes")))
                except OSError:
                    sig = ()
                if sig != topo_sig or (not show_mode() and now - topo_t >= 600) or (not topo and now - topo_t >= 120):
                    t = disk_topology()
                    topo_sig, topo_t = sig, now          # even if empty: retry in 2 minutes, not every round
                    if t:
                        topo = t
                if now - free_t >= (10 if watch else 30) or not free:
                    free_t = now
                    for v in topo:
                        try:
                            s = os.statvfs(v["mnt"])
                            free[v["mnt"]] = (s.f_bavail * s.f_frsize / 1024 ** 3, s.f_blocks * s.f_frsize / 1024 ** 3)
                        except OSError:
                            free[v["mnt"]] = (None, None)
                try:
                    rates = io_rates(parse_io(run(["ioreg", "-r", "-c", "IOBlockStorageDriver", "-d", "2", "-w0"], timeout=6)), now)
                except Exception:
                    rates = {}
                kio = key_io(now)
                if watch and not show_mode() and now - files_t >= 20:
                    files_t = now
                    files = key_files(topo)
                use = topo or [{"mnt": "/", "name": "Macintosh HD", "bsd": "", "internal": True, "ssd": True, "smart": "", "bus": ""}]
                if not topo and "/" not in free:
                    try:
                        du = shutil.disk_usage("/")
                        free["/"] = (du.free / 1024 ** 3, du.total / 1024 ** 3)
                    except OSError:
                        pass
                vols, sysd, key = disk_build(use, free, rates, kio, files, now)
                with disk_lock:
                    disk.update(vols=vols, sys=sysd, key=key, t=now)
                stats["dsk"] = sysd
                stats["disk"] = sysd["free"]
        except Exception as e:
            print("disk:", e)
        time.sleep(1.0)


def disk_view():
    disk["watch"] = time.time()
    with disk_lock:
        return {"vols": list(disk["vols"]), "sys": disk["sys"], "key": disk["key"], "key_app": config.get("key_app", ""),
                "key_running": bool(key_pids), "show": show_mode(), "t": disk["t"], "now": time.time(),
                "limits": {"free": [DISK_FREE_Y, DISK_FREE_R], "pct": [DISK_PCT_Y, DISK_PCT_R],
                           "ssd": list(DISK_LAT[True]), "hdd": list(DISK_LAT[False])}}


def env_loop():
    last = {"temp": 0.0, "batt": 0.0, "therm": 0.0}
    fails, pause_until, has_batt = 0, 0.0, True
    while True:
        now = time.time()
        if now - last["temp"] >= 30 and now >= pause_until:
            last["temp"] = now
            try:
                r = subprocess.run([sys.executable, "-S", os.path.join(os.path.dirname(os.path.abspath(__file__)), "endurance_temp.py")],
                                   capture_output=True, text=True, timeout=10, env=ENV)
                m = re.search(r"TEMP\|([\d.]+)", r.stdout)
                stats["temp"] = round(float(m.group(1)), 1) if m else None
                fails = 0 if m else fails + 1
            except Exception:
                stats["temp"] = None
                fails += 1
            if fails >= 3:               # not available on this Mac: retry in 10 minutes
                pause_until, fails = now + 600, 0
        if now - last["batt"] >= (30 if has_batt else 600):     # a Mac without a battery is not queried every 30 s
            last["batt"] = now
            try:
                stats["batt"] = read_batt()
            except Exception:
                stats["batt"] = None
            has_batt = stats["batt"] is not None
        if now - last["therm"] >= 30:
            last["therm"] = now
            try:
                stats["thr"] = read_therm()
            except Exception:
                stats["thr"] = None
        time.sleep(1.0)


# ---- DEFCON: risk level (audio glitch, QLab stop, host Mac crash) and history ----
DEFCON_DIR = os.path.join(os.path.expanduser("~"), "Library", "Application Support", "The Endurance")
DEFCON_SAMPLES = os.path.join(DEFCON_DIR, "defcon-log.jsonl")
DEFCON_EVENTS = os.path.join(DEFCON_DIR, "defcon-events.jsonl")
DEFCON_SENS_CFG = os.path.join(DEFCON_DIR, "defcon-sensitivity")
DEFCON_HOLD_HI = 10.0      # seconds DEFCON 2 or 1 stays visible after being reached
DEFCON_HOLD = 4.0           # seconds the worst level stays visible before dropping
SAMPLES_MAX = 12000          # about 33 hours at one sample every 10 seconds
EVENTS_MAX = 1000
SENS = {"normal": {"pct": 0, "temp": 0, "swap": 1.0},
        "strict": {"pct": -10, "temp": -6, "swap": 0.5}}
defcon = {"level": 5, "raw": 5, "why": [], "blink": 0, "sens": "normal", "since": time.time()}
defcon_lock = threading.Lock()
defcon_hist = deque()
defcon_low = [None]          # since the raw level has been 2 or 1 without interruption
defcon_events = deque(maxlen=EVENTS_MAX)
defcon_samples = deque(maxlen=SAMPLES_MAX)
defcon_last_sample = [0.0]


def defcon_eval(sn, sens="normal"):
    """Risk score -> (level 5..1, reasons). None if the basic data is missing."""
    k = SENS.get(sens, SENS["normal"])
    sh = k["pct"]
    cpu, ram, pr, sw = sn.get("cpu"), sn.get("ram"), sn.get("pr"), sn.get("swap")
    cores, types = sn.get("cores"), sn.get("types")
    if cpu is None and ram is None:
        return None
    pts, why, floor2 = 0, [], False
    split = bool(cores and types and len(cores) == len(types))
    # total CPU and P-cores measure the same load: the higher of the two counts, not the sum
    cand = []
    if cpu is not None:
        t1, t2, t3 = ((70, 85, 95) if split else (65, 80, 92))
        for t, p in ((t3, 3), (t2, 2), (t1, 1)):
            if cpu >= t + sh:
                cand.append((p, "CPU %d%%" % round(cpu)))
                break
    if split:
        pc = [v for v, ty in zip(cores, types) if ty == "P"]
        if pc:
            a = sum(pc) / len(pc)
            for t, p in ((95, 3), (85, 2), (70, 1)):
                if a >= t + sh:
                    cand.append((p, "P-CORES %d%%" % round(a)))
                    break
    if cand:
        best = max(cand, key=lambda c: c[0])
        pts += best[0]
        why.append(best[1])
    if ram is not None:
        # full RAM with normal pressure is normal in macOS (cache): it weighs at most 1 point
        for t, p in ((97, 3), (92, 2), (85, 1)):
            if ram >= t + sh:
                if pr is not None and pr <= 1:
                    p = min(p, 1)
                pts += p
                why.append("RAM %d%%" % round(ram))
                break
    if pr is not None:
        if pr >= 3:
            pts += 4
            why.append("MEM PRESSURE CRITICAL")
        elif pr == 2:
            pts += 2
            why.append("MEM PRESSURE WARN")
    if sw is not None:
        if sw >= 4 * k["swap"]:
            pts += 2
            why.append("SWAP %.1fGB" % sw)
        elif sw >= 2 * k["swap"]:
            pts += 1
            why.append("SWAP %.1fGB" % sw)
    tp = sn.get("temp")
    if tp is not None:
        for t, p in ((90, 3), (82, 2), (72, 1)):
            if tp >= t + k["temp"]:
                pts += p
                why.append("CPU TEMP %d C" % round(tp))
                break
    thr = sn.get("thr")
    if thr is not None and thr < 100:
        pts += 2
        why.append("THERMAL LIMIT %d%%" % thr)
    b = sn.get("batt")
    if b and b.get("src") == "BATT" and b["pct"] <= 50:
        pts += 1
        why.append("ON BATTERY %d%%" % b["pct"])
        if b["pct"] <= 30:
            pts += 1
        if b["pct"] <= 15:
            pts += 1
    dk = sn.get("disk")
    if dk is not None:
        for t, p in ((5, 3), (10, 2), (20, 1)):
            if dk < t:
                pts += p
                why.append("DISK %.0fGB FREE" % dk)
                break
        if dk < 2:
            floor2 = True
    dsk = sn.get("dsk") or {}
    if dsk.get("llv", 1) >= 3:
        pts += 2
        why.append("DISK SLOW %dms" % round(dsk.get("lat") or 0))
    elif dsk.get("llv", 1) == 2:
        pts += 1
        why.append("DISK SLOW %dms" % round(dsk.get("lat") or 0))
    if dsk.get("smart_bad"):
        pts += 3
        why.append("DISK FAILING")
        floor2 = True
    # The key app (usually QLab) only weighs if it is running and using a lot: if it is closed, only the global resources count.
    ky = sn.get("key")
    if ky and ky.get("running"):
        nc = sn.get("ncores") or (len(cores) if cores else 1) or 1
        kc = (ky.get("cpu") or 0) / max(1, nc)
        for t, p in ((75, 2), (50, 1)):
            if kc >= t:
                pts += p
                why.append("%s CPU %d%%" % (str(ky.get("name", "KEY APP")).upper(), round(kc)))
                break
        tot = sn.get("total")
        if tot and (ky.get("gb") or 0) / tot * 100 >= 50 and (ram is None or ram >= 80):
            pts += 1
            why.append("%s RAM %.1fGB" % (str(ky.get("name", "KEY APP")).upper(), ky.get("gb")))
    lv = 1 if pts >= 7 else 2 if pts >= 5 else 3 if pts >= 3 else 4 if pts >= 2 else 5
    if pr is not None and pr >= 3:
        if (sw is not None and sw >= 3) or (ram is not None and ram >= 95):
            lv = 1
        elif lv > 2:
            lv = 2
    if ram is not None and ram >= 97 and pr is not None and pr >= 2:
        lv = 1
    if floor2 and lv > 2:
        lv = 2
    return lv, why


def _core_avgs(cores, types):
    if not cores or not types or len(cores) != len(types):
        return None, None
    p = [v for v, t in zip(cores, types) if t == "P"]
    e = [v for v, t in zip(cores, types) if t == "E"]
    return (sum(p) / len(p) if p else None), (sum(e) / len(e) if e else None)


def _append_jsonl(path, obj):
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(obj, separators=(",", ":")) + "\n")
    except OSError:
        pass


def defcon_snapshot():
    with lock:
        n_cues = len([u for u in order if cues.get(u)])
    return {"cpu": stats.get("cpu"), "ram": stats.get("ram"), "pr": stats.get("pressure"), "swap": stats.get("swap"),
            "cores": stats.get("cores"), "types": stats.get("core_types"), "temp": stats.get("temp"),
            "thr": stats.get("thr"), "batt": stats.get("batt"), "disk": stats.get("disk"), "dsk": stats.get("dsk"),
            "online": time.time() - last_reply < 3, "ncues": n_cues, "key": stats.get("key"),
            "ncores": stats.get("ncores"), "total": stats.get("total")}


def defcon_step(now=None, sn=None):
    now = now if now is not None else time.time()
    sn = sn or defcon_snapshot()
    with defcon_lock:
        sens = defcon["sens"]
    r = defcon_eval(sn, sens)
    if r is None:
        return
    lv, why = r
    with defcon_lock:
        defcon_hist.append((now, lv, why))
        while defcon_hist and now - defcon_hist[0][0] > DEFCON_HOLD_HI:
            defcon_hist.popleft()
        # DEFCON 2 or 1: the worst level reached stays for 10 s (easy to read, and 2-1-2 does not make the instructions jump around);
        # for levels 3-5 the earlier short window applies
        worst = defcon_hist[0]
        for h in defcon_hist:
            if h[1] <= worst[1]:
                worst = h
        if worst[1] > 2:
            worst = None
            for h in defcon_hist:
                if now - h[0] <= DEFCON_HOLD and (worst is None or h[1] <= worst[1]):
                    worst = h
            worst = worst or defcon_hist[-1]
        shown, swhy = worst[1], worst[2]
        if lv <= 2:
            if defcon_low[0] is None:
                defcon_low[0] = now
        else:
            defcon_low[0] = None
        crit = sn.get("pr") is not None and sn["pr"] >= 3
        blink = 0
        if lv <= 2 and defcon_low[0] is not None and (now - defcon_low[0] >= 10 or crit):
            blink = 1 if lv == 1 else 2
        if shown != defcon["level"]:
            ev = {"t": round(now, 1), "type": "level", "from": defcon["level"], "to": shown, "why": swhy,
                  "apps": apps_now(), "res": res_snapshot()}
            defcon_events.append(ev)
            _append_jsonl(DEFCON_EVENTS, ev)
            defcon["since"] = now
        defcon.update(level=shown, raw=lv, why=swhy, blink=blink)
    if now - defcon_last_sample[0] >= 10:
        defcon_last_sample[0] = now
        p, e = _core_avgs(sn.get("cores"), sn.get("types"))
        b = sn.get("batt") or {}
        smp = {"t": round(now, 1), "lv": lv, "cpu": sn.get("cpu"), "p": None if p is None else round(p, 1),
               "e": None if e is None else round(e, 1), "ram": sn.get("ram"), "pr": sn.get("pr"), "swap": sn.get("swap"),
               "temp": sn.get("temp"), "bat": b.get("pct"), "src": b.get("src"), "thr": sn.get("thr"),
               "disk": sn.get("disk"), "dr": (sn.get("dsk") or {}).get("r"), "dw": (sn.get("dsk") or {}).get("w"),
               "dl": (sn.get("dsk") or {}).get("lat"), "q": 1 if sn.get("online") else 0, "cues": sn.get("ncues"),
               "cores": [round(c) for c in (sn.get("cores") or [])], "apps": apps_now(),
               "kr": 1 if (sn.get("key") or {}).get("running") else 0}
        with defcon_lock:
            defcon_samples.append(smp)
        _append_jsonl(DEFCON_SAMPLES, smp)


# ---- Impostazioni utente (app chiave, ruoli main / backup), salvate accanto al log DEFCON ----
CONFIG_FILE = os.path.join(DEFCON_DIR, "config.json")
config = {"key_app": "QLab", "roles": {}, "mode": "edit"}      # roles: "self" or ip -> "main" | "backup"
config_lock = threading.Lock()
running_apps = []                              # running apps (.app), to choose the key app
apps_mem = []                                  # the apps using the most RAM


def _migrate_old_dir():
    """The Endurance used to be: if the folder of The Magi System still exists and the new one does not, it is copied (log, roles, settings)."""
    old = os.path.join(os.path.expanduser("~"), "Library", "Application Support", "The Magi System")
    if os.path.isdir(old) and not os.path.exists(DEFCON_DIR):
        try:
            shutil.copytree(old, DEFCON_DIR)
        except OSError:
            pass


def config_load():
    try:
        with open(CONFIG_FILE, encoding="utf-8") as f:
            d = json.load(f)
        if isinstance(d.get("key_app"), str):
            config["key_app"] = key_canon(d["key_app"]) or "QLab"
        if isinstance(d.get("kd"), dict):
            config["kd"] = {k: v for k, v in d["kd"].items() if k in KD_KEYS and isinstance(v, (str, int))}
        config["lp_extra"] = bool(d.get("lp_extra")) and config.get("key_app") == "QLab"
        if d.get("mode") in ("edit", "show"):
            config["mode"] = d["mode"]
        if isinstance(d.get("roles"), dict):
            config["roles"] = {k: v for k, v in d["roles"].items() if v in ("main", "backup") and (k == "self" or _valid_ip(k))}
    except (OSError, ValueError):
        pass


def config_save():
    try:
        os.makedirs(DEFCON_DIR, exist_ok=True)
        with config_lock:
            data = json.dumps(config)
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            f.write(data)
    except OSError:
        pass


def show_mode():
    return config.get("mode") == "show"


def mode_set(m):
    """EDIT: everything is allowed from the app. SHOW: autosave, OSC monitor and network discovery are off and locked
    (also the automatic network scan); the DEFCON log stays, as it weighs very little."""
    if m not in ("edit", "show"):
        return False
    with config_lock:
        config["mode"] = m
    defcon_set_sens("normal" if m == "show" else "strict")      # SHOW = normal, EDIT = strict
    if m == "show":
        with autosave_lock:
            mins = autosave["minutes"]
        autosave_set(False, mins)
        osc_set(False)
        discover_clear()
    config_save()
    return True


def _valid_ip(ip):
    try:
        a = ipaddress.IPv4Address(ip)
        return a.is_private and not a.is_loopback and not a.is_link_local
    except ValueError:
        return False


def _norm(x):
    return re.sub(r"[^a-z0-9]", "", str(x).lower())


def key_match(name, key):
    n = _norm(name)
    return any(n == k or (len(k) >= 3 and k in n) for k in key_pats(key))


LPQ = "QLab + Live Professor"      # QLab as key app, plus the LiveProfessor DSP load always in view


def key_set(name):
    stats["key2"] = None
    extra = _norm(name) == _norm(LPQ)
    name = "QLab" if extra else (key_canon(name) if (name or "").strip() else "")
    if name is None:
        return None
    with config_lock:
        config["key_app"] = name
        config["lp_extra"] = extra
    stats["key"] = None
    config_save()
    return name


def roles_set(target, role):
    """target: "self" or an IP address. Only one main and one backup at a time; the host can be either."""
    if target != "self" and not _valid_ip(target):
        return False
    if role not in ("main", "backup", "none"):
        return False
    with config_lock:
        r = config["roles"]
        if role == "none":
            r.pop(target, None)
        else:
            for k in [k for k, v in r.items() if v == role]:
                del r[k]
            r[target] = role
    config_save()
    return True


def role_ip(role):
    with config_lock:
        return next((k for k, v in config["roles"].items() if v == role and k != "self"), None)


def apps_now():
    """The apps in use right now (top 5 by CPU, plus the key app if it is not among them): [name, cpu %, GB]."""
    out = [[a["name"], a["cpu"], a["gb"]] for a in (stats.get("apps") or [])[:5]]
    ky = stats.get("key")
    if ky and ky.get("running") and not any(key_match(o[0], ky["name"]) for o in out):
        out.append([ky.get("app") or ky["name"], ky.get("cpu"), ky.get("gb")])
    return out


def res_snapshot():
    p, e = _core_avgs(stats.get("cores"), stats.get("core_types"))
    b = stats.get("batt") or {}
    return {"cpu": stats.get("cpu"), "p": None if p is None else round(p, 1), "e": None if e is None else round(e, 1),
            "ram": stats.get("ram"), "pr": stats.get("pressure"), "swap": stats.get("swap"), "temp": stats.get("temp"),
            "thr": stats.get("thr"), "bat": b.get("pct"), "src": b.get("src"), "disk": stats.get("disk"), "dl": (stats.get("dsk") or {}).get("lat"), "lv": defcon["level"]}


# ---- Key app and app crashes: if an app disappears from the process list and macOS writes a crash report, it is logged ----
DIAG_DIRS = [os.path.join(os.path.expanduser("~"), "Library", "Logs", "DiagnosticReports"), "/Library/Logs/DiagnosticReports"]
crash_prev = {}        # nome app -> {"n": giri in cui e' stata vista, "exe", "cpu", "gb", "pids"}
crash_last = {"t": None, "snap": None, "apps": []}
crash_pending = []     # apps that disappeared, waiting for the crash report


def find_crash_report(name, exe, since):
    """Name of the crash report (.ips / .crash) written after `since` for this app, or None."""
    names = {_norm(name), _norm(exe)} - {""}
    best = None
    for d in DIAG_DIRS:
        try:
            files = os.listdir(d)
        except OSError:
            continue
        for fn in files:
            if not fn.lower().endswith((".ips", ".crash")):
                continue
            base = re.split(r"[-_ ]?\d{4}-\d{2}-\d{2}", fn, 1)[0]
            if _norm(base) not in names:
                continue
            try:
                mt = os.path.getmtime(os.path.join(d, fn))
            except OSError:
                continue
            if mt >= since - 5 and (best is None or mt > best[0]):
                best = (mt, fn)
    return best[1] if best else None


def log_crash(pe, rep):
    ev = {"t": round(pe["t"], 1), "type": "crash" if rep else "closed", "seen": round(pe["seen"], 1), "app": pe["name"],
          "key": pe["key"], "report": rep or "", "res": pe["snap"] or {}, "apps": pe["apps"],
          "app_cpu": pe["cpu"], "app_gb": pe["gb"]}
    with defcon_lock:
        defcon_events.append(ev)
    _append_jsonl(DEFCON_EVENTS, ev)


def crash_watch(agg, meta, now, key):
    cur = {n for n in agg if n != APP_NAME and meta.get(n, [False])[0]}
    for n in list(crash_prev):
        p = crash_prev[n]
        if n not in cur or not (p["pids"] & meta[n][2]):          # gone, or reopened with new processes
            if n not in cur:
                del crash_prev[n]
            if p["n"] >= 2:
                crash_pending.append({"name": n, "exe": p["exe"], "t": now, "seen": crash_last["t"] or now, "snap": crash_last["snap"],
                                      "apps": crash_last["apps"], "cpu": p["cpu"], "gb": p["gb"],
                                      "key": bool(key) and key_match(n, key)})
            if n in cur:
                p.update(n=0)
    for n in cur:
        p = crash_prev.setdefault(n, {"n": 0, "exe": meta[n][1], "cpu": 0, "gb": 0, "pids": set()})
        p["n"] += 1
        p["cpu"], p["gb"], p["pids"] = round(agg[n][0], 1), round(agg[n][1], 2), set(meta[n][2])
    crash_last.update(t=now, snap=res_snapshot(),
                      apps=[[k, round(v[0], 1), round(v[1], 2)] for k, v in sorted(agg.items(), key=lambda kv: kv[1][0], reverse=True)[:5] if v[0] > 0])
    keep = []
    for pe in crash_pending:
        rep = find_crash_report(pe["name"], pe["exe"], pe["seen"])
        if rep:
            log_crash(pe, rep)
        elif now - pe["t"] < 120:
            keep.append(pe)
        elif pe["key"]:
            log_crash(pe, None)          # only the key app closed without a report is logged: for the others a normal close is not a crash
    crash_pending[:] = keep


def key_update(agg, meta, now):
    key = (config.get("key_app") or "").strip()
    info = None
    if key:
        cpu = gb = 0.0
        found = []
        for n, v in agg.items():
            if n != APP_NAME and key_match(n, key):
                cpu += v[0]
                gb += v[1]
                found.append(n)
        info = {"name": key, "running": bool(found), "app": found[0] if found else "", "cpu": round(cpu, 1), "gb": round(gb, 2)}
    stats["key"] = info
    info2 = None
    if config.get("lp_extra"):
        c2 = g2 = 0.0
        f2 = []
        for n, v in agg.items():
            if n != APP_NAME and key_match(n, "Live Professor"):
                c2 += v[0]
                g2 += v[1]
                f2.append(n)
        info2 = {"name": "Live Professor", "running": bool(f2), "app": f2[0] if f2 else "", "cpu": round(c2, 1), "gb": round(g2, 2)}
    stats["key2"] = info2
    kp = set()
    if info:
        for n in found:
            kp |= set(meta[n][2])
    key_pids[:] = sorted(kp)
    running_apps[:] = sorted(n for n in agg if n != APP_NAME and meta.get(n, [False])[0])
    apps_mem[:] = [[n, round(v[1], 2)] for n, v in sorted(agg.items(), key=lambda kv: kv[1][1], reverse=True)[:5] if n != APP_NAME]
    crash_watch(agg, meta, now, key)


# ---- Ping of the network machines ----
pings = {}              # ip -> {"ok", "sent", "got", "loss", "min", "avg", "max", "t"}
_ping_locks = {}
_ping_locks_lock = threading.Lock()


def ping_run(ip, count=3):
    if not _valid_ip(ip) or ip_excluded(ip):
        return None
    with _ping_locks_lock:
        lk = _ping_locks.setdefault(ip, threading.Lock())
    if not lk.acquire(timeout=0.01):               # already running: the last result is returned
        return pings.get(ip)
    try:
        cmd = (["ping", "-c", str(count), "-t", "5"] if sys.platform == "darwin" else ["ping", "-c", str(count), "-W", "1"]) + [ip]
        out = ""
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=10, env=ENV)
            out = (r.stdout or "") + (r.stderr or "")
        except Exception:
            pass
        m = re.search(r"(\d+)\s+packets transmitted,\s+(\d+)\s+(?:packets )?received", out)
        sent, got = (int(m.group(1)), int(m.group(2))) if m else (count, 0)
        t = re.search(r"=\s*([\d.]+)/([\d.]+)/([\d.]+)", out)
        res = {"ok": got > 0, "sent": sent, "got": got, "loss": round(100 - got * 100.0 / max(1, sent)),
               "min": float(t.group(1)) if t else None, "avg": float(t.group(2)) if t else None,
               "max": float(t.group(3)) if t else None, "t": round(time.time(), 1)}
        pings[ip] = res
        return res
    finally:
        lk.release()


def backup_loop():
    """If there is a main or backup machine on the network, one ping every 30 seconds to know whether it answers."""
    time.sleep(5)
    while True:
        try:
            for role in ("main", "backup"):
                ip = role_ip(role)
                if ip:
                    ping_run(ip, 1)
        except Exception as e:
            print("backup_loop:", e)
        time.sleep(30)


# ---- Advice: when to get ready for the backup machine ----
# Guidelines per app type: show apps react differently to overload.
APP_CATS = [
    ("video", ("qlab", "resolume", "millumin", "madmapper", "touchdesigner", "isadora", "notch", "unity", "unreal", "blender",
               "resolve", "premiere", "aftereffects", "finalcut", "obs", "vlc", "watchout", "pixera", "disguise", "modul8", "vdmx",
               "keynote", "powerpoint")),
    ("audio", ("logic", "ableton", "liveprofessor", "protools", "reaper", "mainstage", "dantevirtual", "dantecontroller", "audiohijack",
               "smaart", "soundbase", "wsm", "workbench", "compass", "r1", "bitwig", "cubase", "nuendo", "studioone", "totalmix")),
    ("control", ("companion", "bitfocus", "lightkey", "onyx", "chamsys", "grandma", "madrix", "touchosc", "vectorworks")),
]
CAT_TEXT = {"video": "video and graphics apps need RAM and GPU: stutter and dropped frames come first",
            "audio": "audio apps need a steady CPU: clicks and dropouts come as soon as CPU or memory pressure spikes",
            "control": "control and lighting apps stop sending cues when the Mac stalls"}


def app_cat(name):
    k = _norm(name)
    for cat, keys in APP_CATS:
        for p in keys:
            if (k == p) if len(p) <= 3 else (p in k):
                return cat
    return None


def backup_target():
    with config_lock:
        roles = dict(config["roles"])
    if roles.get("self") == "backup":
        return {"self_backup": True}
    ip = next((k for k, v in roles.items() if v == "backup" and k != "self"), None)
    if not ip:
        return None
    name = ""
    with peers_lock:
        if ip in peers:
            name = peers[ip].get("host") or ""
    with disc_lock:
        for h in disc["hosts"]:
            if h.get("ip") == ip and h.get("name"):
                name = name or h["name"]
    pg = pings.get(ip)
    reach = None
    if pg and time.time() - pg["t"] < 120:
        reach = bool(pg["ok"])
    return {"ip": ip, "name": name, "reach": reach}


DEFCON_ACT = (("DISK FAILING", "Stop writing. Switch to backup."), ("DISK SLOW", "Stop other disk work."),
              ("DISK ", "Free disk space."), ("MEM PRESSURE", "Close apps."), ("SWAP", "Close apps."),
              ("RAM", "Close apps."), ("CPU TEMP", "Improve cooling."), ("THERMAL", "Improve cooling."),
              ("ON BATTERY", "Plug in power."))


def advice_calc():
    """Based on the DEFCON level, the resources used and the type of the most active apps, tells whether to get ready for the backup machine."""
    with defcon_lock:
        d = dict(defcon)
    lv, now = d["level"], time.time()
    stage = 3 if lv <= 1 else 2 if lv == 2 else 1 if (lv == 3 and now - d["since"] >= 10) else 0
    if not stage:
        return {"stage": 0}
    key = (config.get("key_app") or "").strip()
    rows = {}
    for a in (stats.get("apps") or []):
        if a["cpu"] >= 15 or a["gb"] >= 1.0:
            rows[a["name"]] = (a["cpu"], a["gb"])
    for n, gb in apps_mem[:3]:
        if gb >= 1.5:
            rows.setdefault(n, (0.0, gb))
    ky = stats.get("key")
    if ky and ky.get("running"):
        rows.setdefault(ky.get("app") or ky["name"], (ky["cpu"], ky["gb"]))
    show = [n for n in rows if app_cat(n) or (key and key_match(n, key))]
    other = [n for n in rows if n not in show]
    bt = backup_target()
    rs = list(d.get("why") or [])
    why = ", ".join(rs[:3])
    act = ""
    for r in rs:                                   # first useful action based on the worst reason
        for k, t in DEFCON_ACT:
            if r.startswith(k):
                act = t
                break
        if act:
            break
    close = ("Close " + ", ".join(other[:3]) + ".") if other else ""
    if act == "Close apps." and close:
        act = close
    if bt and bt.get("self_backup"):
        return {"stage": stage, "title": "THIS BACKUP IS LOADED", "text": (why + ". " if why else "") + "It may not take over.", "apps": show + other, "backup": None}
    if not bt:
        bk = "No backup set."
    else:
        bk = "Backup %s%s" % ((bt.get("name") + " " if bt.get("name") else "") + bt["ip"], "" if bt["reach"] is None else ": OK" if bt["reach"] else ": NO PING!")
    if stage == 1:
        title = "BACKUP: STAND BY"
        text = "%s. %s %s" % (why or "Load rising", act or close or "Check the backup.", bk)
    elif stage == 2:
        title = "BACKUP: GET READY"
        text = "%s. %s %s" % (why, act or close or "Backup online, show open.", bk)
    else:
        title = "BACKUP: SWITCH NOW"
        text = "%s. %s %s" % (why, act or "Switch to the backup.", bk)
    return {"stage": stage, "title": title, "text": " ".join(text.split()), "apps": show + other, "backup": bt}


def defcon_loop():
    while True:
        time.sleep(1.0)
        try:
            defcon_step()
        except Exception as e:
            print("defcon:", e)


def defcon_load():
    """Resumes history and sensitivity from last time (the level restarts from 5)."""
    for path, dq in ((DEFCON_SAMPLES, defcon_samples), (DEFCON_EVENTS, defcon_events)):
        try:
            with open(path, encoding="utf-8") as f:
                lines = f.readlines()[-dq.maxlen:]
            for ln in lines:
                try:
                    dq.append(json.loads(ln))
                except ValueError:
                    pass
            with open(path, "w", encoding="utf-8") as f:     # keeps the file within the limit
                f.writelines(lines)
        except OSError:
            pass
    try:
        with open(DEFCON_SENS_CFG) as f:
            v = f.read().strip()
        if v in SENS:
            defcon["sens"] = v
    except OSError:
        pass


def defcon_set_sens(v):
    if v not in SENS:
        return False
    with defcon_lock:
        defcon["sens"] = v
    try:
        os.makedirs(DEFCON_DIR, exist_ok=True)
        with open(DEFCON_SENS_CFG, "w") as f:
            f.write(v)
    except OSError:
        pass
    return True


def defcon_clear():
    with defcon_lock:
        defcon_samples.clear()
        defcon_events.clear()
    for path in (DEFCON_SAMPLES, DEFCON_EVENTS):
        try:
            open(path, "w").close()
        except OSError:
            pass


def defcon_view():
    now = time.time()
    with defcon_lock:
        d = dict(defcon)
        ev = list(defcon_events)[-100:][::-1]
        smp = list(defcon_samples)
    strip = [0] * 60
    for s in smp:
        age = int((now - s["t"]) // 60)
        if 0 <= age < 60:
            i = 59 - age
            strip[i] = s["lv"] if not strip[i] else min(strip[i], s["lv"])
    return {"defcon": d, "events": ev, "strip": strip, "samples": len(smp), "first": smp[0]["t"] if smp else None,
            "now": now, "recent": smp[-12:][::-1], "key": stats.get("key"), "key_app": config.get("key_app", ""),
            "crashes": sum(1 for e in ev if e.get("type") == "crash")}


def _ts(t):
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(t))


def _f(v, fmt="%.0f", none="-"):
    return none if v is None else fmt % v


def defcon_csv():
    with defcon_lock:
        smp = list(defcon_samples)
    rows = ["time,defcon,cpu_pct,p_cores_pct,e_cores_pct,ram_pct,mem_pressure,swap_gb,cpu_temp_c,battery_pct,power,thermal_limit_pct,disk_free_gb,disk_read_mbs,disk_write_mbs,disk_latency_ms,qlab_online,active_cues,per_core_pct,apps_in_use,key_app_running,event"]
    for s in smp:
        apps = "|".join("%s:%s%%:%sGB" % (a[0].replace(",", " "), a[1], a[2]) for a in s.get("apps", []))
        rows.append(",".join(str(x) for x in (
            _ts(s["t"]), s["lv"], _f(s.get("cpu"), "%.1f", ""), _f(s.get("p"), "%.1f", ""), _f(s.get("e"), "%.1f", ""),
            _f(s.get("ram"), "%.1f", ""), _f(s.get("pr"), "%d", ""), _f(s.get("swap"), "%.2f", ""),
            _f(s.get("temp"), "%.1f", ""), _f(s.get("bat"), "%d", ""), s.get("src") or "", _f(s.get("thr"), "%d", ""),
            _f(s.get("disk"), "%.1f", ""), _f(s.get("dr"), "%.1f", ""), _f(s.get("dw"), "%.1f", ""), _f(s.get("dl"), "%.1f", ""), s.get("q", ""), s.get("cues", ""), "|".join(str(c) for c in s.get("cores", [])), apps,
            s.get("kr", ""), "")))
    with defcon_lock:
        evs = list(defcon_events)
    for e in evs:
        r = e.get("res") or {}
        if e.get("type") in ("crash", "closed"):
            note = "%s %s%s report=%s app_cpu=%s app_gb=%s" % ("CRASH" if e["type"] == "crash" else "KEY APP CLOSED", e.get("app", "?"),
                                                           " (key app)" if e.get("key") else "", e.get("report") or "-", e.get("app_cpu", ""), e.get("app_gb", ""))
        else:
            note = "DEFCON %s -> %s: %s" % (e.get("from"), e.get("to"), " / ".join(e.get("why") or []))
        apps = "|".join("%s:%s%%:%sGB" % (a[0].replace(",", " "), a[1], a[2]) for a in e.get("apps", []))
        rows.append(",".join(str(x) for x in (
            _ts(e["t"]), e.get("to", r.get("lv", "")), _f(r.get("cpu"), "%.1f", ""), _f(r.get("p"), "%.1f", ""), _f(r.get("e"), "%.1f", ""),
            _f(r.get("ram"), "%.1f", ""), _f(r.get("pr"), "%d", ""), _f(r.get("swap"), "%.2f", ""), _f(r.get("temp"), "%.1f", ""),
            _f(r.get("bat"), "%d", ""), r.get("src") or "", _f(r.get("thr"), "%d", ""), _f(r.get("disk"), "%.1f", ""), "", "", _f(r.get("dl"), "%.1f", ""), "", "", "",
            apps, "", note.replace(",", ";"))))
    return ("\n".join(rows) + "\n").encode("utf-8")


def _pdf_escape(s):
    s = s.encode("latin-1", "replace").decode("latin-1")
    return s.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def make_pdf(lines):
    """Write-only PDF (Courier text, A4 landscape), without external libraries."""
    W, H, M, FS, LD = 842, 595, 28, 6.5, 7.6
    per = int((H - 2 * M) // LD)
    pages = [lines[i:i + per] for i in range(0, len(lines), per)] or [[""]]
    n = len(pages)
    objs = [b"<< /Type /Catalog /Pages 2 0 R >>",
            ("<< /Type /Pages /Kids [%s] /Count %d >>" % (" ".join("%d 0 R" % (4 + 2 * i) for i in range(n)), n)).encode(),
            b"<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>"]
    for i, pg in enumerate(pages):
        c = ["BT", "/F1 %.1f Tf" % FS, "%.1f TL" % LD, "%d %.1f Td" % (M, H - M - FS)]
        c += ["(%s) Tj T*" % _pdf_escape(ln[:200]) for ln in pg]
        c += ["ET", "BT", "/F1 6 Tf", "%d 14 Td" % (W // 2 - 30), "(%s) Tj" % ("page %d / %d" % (i + 1, n)), "ET"]
        stream = "\n".join(c).encode("latin-1", "replace")
        objs.append(("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 %d %d] /Resources << /Font << /F1 3 0 R >> >> /Contents %d 0 R >>"
                     % (W, H, 5 + 2 * i)).encode())
        objs.append(b"<< /Length %d >>\nstream\n" % len(stream) + stream + b"\nendstream")
    out, offs = bytearray(b"%PDF-1.4\n"), []
    for i, o in enumerate(objs):
        offs.append(len(out))
        out += b"%d 0 obj\n" % (i + 1) + o + b"\nendobj\n"
    x = len(out)
    out += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objs) + 1) + b"".join(b"%010d 00000 n \n" % o for o in offs)
    out += b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (len(objs) + 1, x)
    return bytes(out)


def defcon_pdf():
    with defcon_lock:
        smp, ev, d = list(defcon_samples), list(defcon_events), dict(defcon)
    L = ["THE ENDURANCE %s - LOG" % VERSION,
         "Host: %s     Exported: %s     DEFCON sensitivity: %s" % (host_name() or "-", _ts(time.time()), d["sens"]),
         "Samples: %d (one every 10 s)%s     DEFCON changes: %d" % (
             len(smp), "     From %s to %s" % (_ts(smp[0]["t"]), _ts(smp[-1]["t"])) if smp else "", len(ev)),
         "DEFCON 5 = no risk ... 1 = glitch or crash imminent. Score from the global resources: CPU, P-cores, RAM, memory pressure, swap, temperature, thermal limit, battery, disk, plus the key app (%s) when it is running." % (config.get("key_app") or "none"),
         "", "== DEFCON CHANGES AND CRASHES ==", "time                 event"]
    for e in ev:
        if e.get("type") in ("crash", "closed"):
            r = e.get("res") or {}
            L.append("%s  %s: %s%s   report: %s" % (_ts(e["t"]), "CRASH" if e["type"] == "crash" else "KEY APP CLOSED (no crash report)",
                                                    e.get("app", "?"), " (KEY APP)" if e.get("key") else "", e.get("report") or "-"))
            L.append("                     at the time: CPU %s%%  RAM %s%%  pressure %s  swap %sGB  temp %s  DEFCON %s  app was using %s%% / %sGB" % (
                _f(r.get("cpu")), _f(r.get("ram")), _f(r.get("pr"), "%d"), _f(r.get("swap"), "%.1f"), _f(r.get("temp")),
                r.get("lv", "-"), e.get("app_cpu", "-"), e.get("app_gb", "-")))
            L.append("                     apps in use: " + ("; ".join("%s %s%%/%sGB" % (a[0][:18], a[1], a[2]) for a in e.get("apps", [])) or "-"))
        else:
            L.append("%s  DEFCON %s -> %s   %s" % (_ts(e["t"]), e.get("from"), e.get("to"), " | ".join(e.get("why") or ["-"])))
            if e.get("apps"):
                L.append("                     apps in use: " + "; ".join("%s %s%%/%sGB" % (a[0][:18], a[1], a[2]) for a in e["apps"]))
    if not ev:
        L.append("(none)")
    L += ["", "== DATA LOG ==",
          "time                 DEF  CPU%  P%   E%   RAM%  PRS  SWAP   TEMP  BAT%  PWR   THR  DISK    R/W MB/s  LAT   QLAB CUES  APPS IN USE (cpu%/GB)  CORES%"]
    for s in smp:
        apps = "; ".join("%s %s/%s" % (a[0][:14], a[1], a[2]) for a in s.get("apps", []))
        L.append("%s  %d    %-5s %-4s %-4s %-5s %-4s %-6s %-5s %-5s %-5s %-4s %-7s %-9s %-5s %-4s %-4s %s  [%s]" % (
            _ts(s["t"]), s["lv"], _f(s.get("cpu"), "%.0f"), _f(s.get("p")), _f(s.get("e")), _f(s.get("ram")),
            _f(s.get("pr"), "%d"), _f(s.get("swap"), "%.1f"), _f(s.get("temp")), _f(s.get("bat"), "%d"),
            s.get("src") or "-", _f(s.get("thr"), "%d"), _f(s.get("disk"), "%.0fGB"),
            "%s/%s" % (_f(s.get("dr"), "%.0f"), _f(s.get("dw"), "%.0f")), _f(s.get("dl"), "%.0f"), "on" if s.get("q") else "off",
            s.get("cues", "-"), apps, ",".join(str(c) for c in s.get("cores", []))))
    if not smp:
        L.append("(no data yet)")
    return make_pdf(L)


# ---- /network page: the Mac's interfaces and discovery of the machines on the network ----
def _mask_to_prefix(m):
    try:
        if m.startswith("0x"):
            return bin(int(m, 16)).count("1")
        return bin(int(ipaddress.ip_address(m))).count("1")
    except Exception:
        return 24


_netall_cache = {"t": 0.0, "v": []}


def net_all():
    """All the Mac's network ports, with the service name shown in System Settings > Network
    (not the hardware one), DHCP / manual configuration and gateway. Result kept for 4 seconds."""
    if time.time() - _netall_cache["t"] < 4 and _netall_cache["v"]:
        return _netall_cache["v"]
    v = _net_all()
    _netall_cache.update(t=time.time(), v=v)
    return v


def _net_all():
    out, seen = [], set()
    svc = net_services()
    try:
        txt = run(["networksetup", "-listallhardwareports"])
    except Exception:
        txt = ""
    for block in txt.split("Hardware Port:")[1:]:
        lines = block.strip().splitlines()
        name = lines[0].strip()
        dev = next((l.split(":", 1)[1].strip() for l in lines if l.startswith("Device:")), "")
        if not dev or dev in seen:
            continue
        seen.add(dev)
        ip, prefix, status, media = "", None, "", ""
        try:
            info = run(["ifconfig", dev], timeout=3)
            m = re.search(r"inet (\d+\.\d+\.\d+\.\d+) netmask (\S+)", info)
            if m:
                ip, prefix = m.group(1), _mask_to_prefix(m.group(2))
            m = re.search(r"status:\s*(\w+)", info)
            status = m.group(1) if m else ""
            m = re.search(r"media:\s*(.+)", info)
            media = m.group(1).strip() if m else ""
        except Exception:
            pass
        low = name.lower()
        kind = "wifi" if ("wi-fi" in low or "wifi" in low or "airport" in low) else \
               "other" if any(w in low for w in ("bluetooth", "bridge", "iphone", "ipad")) else "wired"
        if ip.startswith("169.254."):
            ip = ""
        sv = svc.get(dev) or {}
        out.append({"name": sv.get("service") or name, "hw": name, "dev": dev, "ip": ip, "prefix": prefix, "status": status,
                    "media": media, "kind": kind, "mode": sv.get("mode", ""), "router": sv.get("router", ""),
                    "enabled": sv.get("enabled", True), "order": sv.get("order", 99)})
    out.sort(key=lambda i: i["order"])
    return out


disc = {"ident": 0, "running": False, "dev": "", "done": 0, "total": 0, "hosts": [], "err": None, "finished": None, "started": None}
disc_lock = threading.Lock()


def _arp_table(dev):
    res = {}
    try:
        for ln in run(["arp", "-an"], timeout=5).splitlines():
            m = re.search(r"\((\d+\.\d+\.\d+\.\d+)\) at ([0-9a-fA-F:]+)(?: on (\w+))?", ln)
            if m and "incomplete" not in ln and (not m.group(3) or m.group(3) == dev):
                mac = ":".join(x.zfill(2) for x in m.group(2).split(":"))
                if mac.lower() != "ff:ff:ff:ff:ff:ff":
                    res[m.group(1)] = mac.lower()
    except Exception:
        pass
    return res


def _ping(ip, dev):
    cmd = ["ping", "-c", "1", "-t", "1"] if sys.platform == "darwin" else ["ping", "-c", "1", "-W", "1"]
    if sys.platform == "darwin" and dev:
        cmd += ["-b", dev]
    try:
        r = subprocess.run(cmd + [ip], capture_output=True, timeout=4, env=ENV)
        return r.returncode == 0
    except Exception:
        return False


def _host_label(ip):
    try:
        return socket.gethostbyaddr(ip)[0].split(".local")[0]
    except Exception:
        return ""


# ---- Device recognition: vendor (MAC), Bonjour/mDNS, open ports, web title ----
_oui = {}


def oui_vendor(mac):
    """Vendor from the first 3 bytes of the MAC. 'Private MAC' if it is a random address (iPhone, Android, Windows...)."""
    if not mac:
        return ""
    try:
        first = int(mac[:2], 16)
    except ValueError:
        return ""
    if first & 2:
        return "private MAC"
    if not _oui:
        try:
            import gzip
            with gzip.open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "oui.gz"), "rt", encoding="utf-8") as f:
                for ln in f:
                    _oui[ln[:6]] = ln[7:].strip()
        except Exception:
            _oui["_"] = ""
    return _oui.get(mac.replace(":", "")[:6].upper(), "")


def _dns_name(b, i):
    parts, jumped, end = [], False, i
    for _ in range(60):
        n = b[i]
        if n == 0:
            i += 1
            break
        if n & 0xC0 == 0xC0:
            if not jumped:
                end = i + 2
            i, jumped = ((n & 0x3F) << 8) | b[i + 1], True
            continue
        parts.append(b[i + 1:i + 1 + n].decode("utf-8", "replace"))
        i += 1 + n
    return ".".join(parts), (end if jumped else i)


def mdns_query(ip, qname, timeout=0.8):
    """Queries the device directly on the mDNS port (5353): returns the PTR names of the answer."""
    q = b"".join(bytes([len(p)]) + p.encode() for p in qname.split(".")) + b"\0"
    pkt = struct.pack(">HHHHHH", 0x4d47, 0, 1, 0, 0, 0) + q + struct.pack(">HH", 12, 0x8001)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    names = []
    try:
        s.sendto(pkt, (ip, 5353))
        data, _ = s.recvfrom(4096)
        an = struct.unpack(">H", data[6:8])[0]
        i = 12
        for _ in range(struct.unpack(">H", data[4:6])[0]):
            _, i = _dns_name(data, i)
            i += 4
        for _ in range(an):
            _, i = _dns_name(data, i)
            typ, _, _, ln = struct.unpack(">HHIH", data[i:i + 10])
            i += 10
            if typ == 12:
                names.append(_dns_name(data, i)[0])
            i += ln
    except Exception:
        pass
    finally:
        s.close()
    return names


def open_ports(ip):
    res = []
    for p in PROBE_PORTS:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.35)
        try:
            if s.connect_ex((ip, p)) == 0:
                res.append(p)
        except Exception:
            pass
        finally:
            s.close()
    return res


def http_title(ip, port):
    try:
        import urllib.request
        with urllib.request.urlopen("http://%s:%d/" % (ip, port), timeout=1.2) as r:
            body = r.read(8192).decode("utf-8", "replace")
            srv = r.headers.get("Server", "")
        m = re.search(r"<title[^>]*>\s*([^<]{1,60}?)\s*</title>", body, re.I)
        return (m.group(1) if m else ""), srv
    except Exception:
        return "", ""


AUDIO = ("yamaha", "behringer", "music tribe", "midas", "allen", "focusrite", "rme", "lawo", "digico", "shure",
         "sennheiser", "d&b", "l-acoustics", "meyer", "audinate", "presonus", "motu", "universal audio", "avid",
         "klark", "tc electronic", "soundcraft", "harman", "biamp", "qsc", "crown", "dbx", "lectrosonics", "bose",
         "rcf", "apogee", "ssl", "solid state logic", "studer", "merging", "ravenna", "clear-com", "riedel")
PROBE_PORTS = (22, 80, 443, 445, 515, 548, 554, 631, 1883, 3689, 4440, 5555, 5900, 7000, 8000, 8008, 8009, 8554, 8700, 9100,
               14336, 37777, 53000, 62078)


def ssdp_scan(my_ip, wait=3.0):
    """Looks for UPnP/SSDP devices (TVs, cameras, routers, speakers...) and reads name, vendor and model from their card."""
    found = {}
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((my_ip, 0))
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(my_ip))
        msg = ("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n").encode()
        for _ in range(2):
            s.sendto(msg, ("239.255.255.250", 1900))
        end = time.time() + wait
        while time.time() < end:
            s.settimeout(max(0.1, end - time.time()))
            try:
                data, addr = s.recvfrom(4096)
            except socket.timeout:
                break
            txt = data.decode("utf-8", "replace")
            loc = re.search(r"(?im)^location:\s*(\S+)", txt)
            srv = re.search(r"(?im)^server:\s*(.+)$", txt)
            d = found.setdefault(addr[0], {"loc": "", "server": ""})
            if loc and not d["loc"]:
                d["loc"] = loc.group(1)
            if srv and not d["server"]:
                d["server"] = srv.group(1).strip()
    except Exception:
        pass
    finally:
        s.close()
    return found


def upnp_info(d):
    out = {"friendly": "", "maker": "", "model": "", "dtype": "", "server": d.get("server", "")}
    loc = d.get("loc")
    if loc and loc.startswith("http"):
        try:
            import urllib.request
            with urllib.request.urlopen(loc, timeout=1.5) as r:
                x = r.read(20000).decode("utf-8", "replace")
            for k, tag in (("friendly", "friendlyName"), ("maker", "manufacturer"), ("model", "modelName"), ("dtype", "deviceType")):
                m = re.search(r"<%s>([^<]{1,80})</%s>" % (tag, tag), x)
                if m:
                    out[k] = m.group(1).strip()
        except Exception:
            pass
    return out


def _has(text, words):
    return any(w in text for w in words)


PHONE_V = ("xiaomi", "oppo", "vivo", "oneplus", "huawei device", "realme", "motorola", "nothing technology", "fairphone",
           "zte", "tecno", "infinix", "honor device", "murata", "hmd global")
LAPTOP_V = ("dell", "lenovo", "hewlett", "hp inc", "asustek", "acer", "microsoft corp", "intel corporate", "msi", "micro-star",
            "toshiba", "fujitsu", "razer", "gigabyte", "liteon", "azurewave", "realtek", "qualcomm", "mediatek", "broadcom",
            "chicony", "foxconn", "hon hai", "wistron", "quanta", "compal", "pegatron", "samsung electronics")
TV_V = ("lg electronics", "tcl", "hisense", "vizio", "sharp", "panasonic", "philips", "sony", "roku", "skyworth", "toshiba visual",
        "insignia", "xiaomi tv", "amazon", "google")
CAM_V = ("hikvision", "dahua", "axis comm", "reolink", "amcrest", "wyze", "arlo", "foscam", "vivotek", "hanwha", "bosch security",
         "uniview", "tiandy", "lorex", "swann", "eufy", "anker", "ring", "blink", "nest", "tapo", "mobotix", "avigilon",
         "geovision", "milesight", "panasonic i-pro", "canon", "gopro", "ezviz", "imou", "annke", "zosi")
APPL_V = ("irobot", "roborock", "dyson", "miele", "whirlpool", "electrolux", "bsh", "bosch", "siemens", "haier", "midea",
          "ecovacs", "dreame", "xiaomi", "tuya", "espressif", "shelly", "allterco", "signify", "philips lighting", "sonoff",
          "itead", "ecobee", "honeywell", "tado", "netatmo", "sonos", "meross", "kasa", "lifx", "nanoleaf", "wiz", "yeelight",
          "smartthings", "gree", "daikin", "mitsubishi electric", "samsung", "lg innotek", "rinnai", "weber", "traeger",
          "sharkninja", "ninja", "instant brands", "anova", "withings", "tp-link systems", "wemo", "belkin", "ikea",
          "wyze", "govee", "teckin", "gosund", "hangzhou", "shenzhen", "zhejiang", "guangdong", "ningbo", "beken", "azurewave",
          "murata", "hui zhou", "liteon")
CONSOLE_V = ("nintendo", "sony interactive", "microsoft xbox", "valve")
NAME_HINTS = (
    ("iphone", "iPhone"), ("ipad", "iPad"), ("macbook", "MacBook (laptop)"), ("imac", "iMac"), ("mac-mini", "Mac mini"),
    ("macmini", "Mac mini"), ("mac-studio", "Mac Studio"), ("macstudio", "Mac Studio"), ("apple-tv", "Apple TV"),
    ("appletv", "Apple TV"), ("homepod", "HomePod speaker"), ("galaxy", "Samsung phone / tablet"), ("pixel", "Google Pixel phone"),
    ("android", "Android phone / tablet"), ("oneplus", "OnePlus phone"), ("xiaomi", "Xiaomi device"), ("redmi", "Xiaomi phone"),
    ("laptop", "Laptop"), ("desktop-", "Windows PC"), ("-pc", "Windows PC"), ("notebook", "Laptop"), ("thinkpad", "Laptop"),
    ("chromecast", "Chromecast"), ("roku", "Roku streaming"), ("firetv", "Amazon Fire TV"), ("fire-tv", "Amazon Fire TV"),
    ("echo", "Amazon Echo speaker"), ("alexa", "Amazon Echo speaker"), ("tv", "Smart TV"), ("bravia", "Sony TV"),
    ("lgwebos", "LG TV"), ("webos", "LG TV"), ("cam", "Camera"), ("ipcam", "IP camera"), ("doorbell", "Video doorbell"),
    ("printer", "Printer"), ("hue", "Philips Hue"), ("sonos", "Sonos speaker"), ("playstation", "PlayStation"), ("ps4", "PlayStation"),
    ("ps5", "PlayStation"), ("xbox", "Xbox"), ("switch", "Nintendo Switch / switch"), ("raspberry", "Raspberry Pi"),
    ("robot", "Robot vacuum"), ("roomba", "Robot vacuum"), ("thermostat", "Thermostat"), ("nest", "Google Nest device"),
    ("espressif", "Smart home device (ESP)"), ("esp-", "Smart home device (ESP)"), ("esp32", "Smart home device (ESP)"),
    ("synology", "NAS"), ("diskstation", "NAS"), ("qnap", "NAS"), ("nas", "NAS"),
)


def guess_type(vendor, ports, services, title, srv, name, up=None):
    """Estimate of the device type from: name, Bonjour/UPnP services, open ports, MAC vendor."""
    up = up or {}
    v = ((vendor or "") + " " + (up.get("maker") or "")).lower()
    sv = " ".join(services).lower()
    nm = ((name or "") + " " + (up.get("friendly") or "") + " " + (up.get("model") or "") + " " + (title or "")).lower()
    dt = (up.get("dtype") or "").lower()
    srvh = ((srv or "") + " " + (up.get("server") or "")).lower()
    P = set(ports)
    # 1) the name or the UPnP card already say it
    if 53000 in P:
        return "Mac with QLab" if _has(v + nm, ("apple", "mac")) or 548 in P else "Computer with QLab"
    if _has(dt, ("mediarenderer",)) and _has(v + nm + srvh, ("tv", "lg", "samsung", "sony", "tcl", "hisense", "vizio", "philips", "panasonic", "sharp")):
        return "Smart TV"
    if _has(dt, ("internetgatewaydevice", "wandevice")):
        return "Router / gateway"
    if _has(dt, ("printer",)):
        return "Printer"
    if _has(dt, ("digitalsecuritycamera", "networkcamera")):
        return "IP camera"
    for key, label in NAME_HINTS:
        if len(key) <= 3:
            if re.search(r"(^|[^a-z])%s([^a-z]|$)" % re.escape(key), nm):
                return label
        elif key in nm:
            return label
    # 2) servizi Bonjour
    if _has(sv, ("_apple-mobdev", "_apple-pairable")) or 62078 in P:
        return "iPhone / iPad"
    if _has(sv, ("_axis-video", "_rtsp", "_onvif", "_hap")) and 554 in P:
        return "IP camera"
    if _has(sv, ("_ipp", "_printer", "_pdl-datastream", "_scanner")) or 9100 in P or 515 in P or 631 in P:
        return "Printer / scanner"
    if _has(sv, ("_googlecast",)) or 8008 in P or 8009 in P:
        return "Smart TV / Chromecast" if _has(v, ("lg", "samsung", "sony", "tcl", "hisense", "vizio", "philips")) else "Chromecast / Google speaker"
    if _has(sv, ("_spotify-connect",)) and not _has(sv, ("_airplay",)):
        return "Smart speaker"
    if "audinate" in v or _has(sv, ("_netaudio", "_dante")) or P & {4440, 8700, 14336}:
        return "Dante audio device"
    # 3) typical camera ports
    if P & {554, 8554, 37777} or (8000 in P and _has(v, CAM_V)) or _has(srvh, ("hikvision", "dahua", "ipcam", "netwave", "boa/")):
        return "IP camera"
    if _has(v, CAM_V) and _has(v, ("hikvision", "dahua", "axis", "reolink", "amcrest", "wyze", "arlo", "foscam", "vivotek", "hanwha", "uniview", "ezviz", "lorex", "swann", "annke", "tapo", "eufy", "mobotix", "milesight", "geovision", "avigilon", "imou", "zosi")):
        return "IP camera"
    # 4) Apple
    if "apple" in v:
        if _has(sv, ("_airplay", "_raop")) and not P & {22, 548, 5900, 445}:
            return "Apple TV / HomePod (AirPlay)"
        if P & {22, 548, 5900, 445} or _has(sv, ("_ssh", "_smb", "_afpovertcp", "_sftp-ssh")):
            return "Mac (laptop or desktop)"
        return "Apple device (iPhone / iPad / Mac)"
    # 5) produttori
    if _has(v, ("raspberry",)):
        return "Raspberry Pi"
    if _has(v, CONSOLE_V):
        return "Game console"
    if _has(v, ("ubiquiti", "netgear", "cisco", "tp-link", "zyxel", "mikrotik", "juniper", "arista", "d-link", "aruba", "linksys",
                "avm", "fritz", "ruckus", "extreme", "luminex", "engenius", "draytek", "tenda", "mercusys", "tplink")) \
            and not _has(nm, ("tapo", "kasa", "plug", "cam")):
        return "Network device (switch / router / AP)"
    if _has(v, ("synology", "qnap", "western digital", "buffalo", "drobo", "asustor", "terramaster")):
        return "NAS / storage"
    if any(a in v for a in AUDIO):
        return "Audio equipment"
    if _has(v, ("tuya", "espressif", "shelly", "allterco", "signify", "sonoff", "itead", "ecobee", "tado", "netatmo", "sonos", "meross",
                "lifx", "nanoleaf", "yeelight", "smartthings", "wemo", "ikea", "govee", "irobot", "roborock", "dyson", "miele",
                "whirlpool", "electrolux", "ecovacs", "dreame", "haier", "midea", "daikin", "withings", "honeywell", "beken")):
        return "Home appliance / smart device"
    if _has(v, ("roku", "tcl", "hisense", "vizio", "skyworth", "lg electronics", "sharp", "panasonic", "philips", "sony")) and not P & {22, 445}:
        return "Smart TV / media device"
    if _has(v, ("amazon",)):
        return "Amazon device (Echo / Fire TV)"
    if _has(v, ("google", "nest")):
        return "Google / Nest device"
    if "private" in v:
        return "Phone / tablet / laptop (random MAC)"
    if _has(v, PHONE_V):
        return "Phone / tablet"
    if _has(v, ("samsung",)):
        return "Samsung phone / TV / appliance"
    if _has(v, LAPTOP_V):
        return "Laptop / PC" if not P & {445, 22} else "PC / server"
    if 445 in P:
        return "Windows PC / NAS"
    if 22 in P:
        return "Computer / server"
    if title or P & {80, 443}:
        return "Device with web page"
    return ""


def identify_host(ip, mac, name, upnp=None):
    out = {"vendor": oui_vendor(mac), "name": name or "", "type": "", "ports": [], "info": ""}
    up = upnp_info(upnp) if upnp else {}
    if up.get("maker") and not out["vendor"]:
        out["vendor"] = up["maker"]
    ports = open_ports(ip)
    services = []
    for n in mdns_query(ip, "_services._dns-sd._udp.local"):
        services.append(n.split(".local")[0])
    host = ""
    rev = ".".join(reversed(ip.split("."))) + ".in-addr.arpa"
    for n in mdns_query(ip, rev):
        host = n.replace(".local", "")
        break
    if not out["name"]:
        out["name"] = host or up.get("friendly", "")
    title, srv = "", ""
    for p in (80, 8080) if 80 in ports else ():
        title, srv = http_title(ip, p)
        break
    if title and not out["name"]:
        out["name"] = title
    out["ports"] = ports
    out["type"] = guess_type(out["vendor"], ports, services, title, srv, out["name"], up)
    bits = [x for x in (up.get("model"), title if title != out["name"] else "") if x]
    out["info"] = " / ".join(bits)[:60]
    return out


def discover_run(dev):
    try:
        if not net_monitored(dev):
            raise RuntimeError("This port is not monitored (Network interfaces tab).")
        info = next((i for i in net_all() if i["dev"] == dev), None)
        if not info or not info["ip"]:
            raise RuntimeError("This connection has no IP address.")
        net_ = ipaddress.ip_network("%s/%d" % (info["ip"], info["prefix"] or 24), strict=False)
        if net_.prefixlen < 22:
            net_ = ipaddress.ip_network("%s/24" % info["ip"], strict=False)
        targets = [str(h) for h in net_.hosts()]
        with disc_lock:
            disc.update(total=len(targets), done=0, hosts=[])
        alive = set()
        ssdp = {}
        st = threading.Thread(target=lambda: ssdp.update(ssdp_scan(info["ip"])), daemon=True)
        st.start()

        def probe(ip):
            if ip == info["ip"] or _ping(ip, dev):
                alive.add(ip)
            with disc_lock:
                disc["done"] += 1
        with ThreadPoolExecutor(max_workers=48) as ex:
            list(ex.map(probe, targets))
        st.join(5)
        arp = _arp_table(dev)
        ips = sorted(alive | {i for i in arp if ipaddress.ip_address(i) in net_}, key=lambda x: ipaddress.ip_address(x))
        with ThreadPoolExecutor(max_workers=16) as ex:
            names = list(ex.map(_host_label, ips))
        hosts = [{"ip": ip, "name": ("This Mac (%s)" % host_name()) if ip == info["ip"] else n, "mac": arp.get(ip, ""),
                  "me": ip == info["ip"], "vendor": "", "type": "", "ports": [], "info": ""} for ip, n in zip(ips, names)]
        with disc_lock:
            disc["hosts"] = list(hosts)      # first the basic list, then it is completed with the recognition
            disc["err"] = None
            disc["ident"] = 0

        def ident(h):
            try:
                if h["me"]:
                    r = {"vendor": oui_vendor(h["mac"]), "type": "This Mac", "ports": [], "info": "", "name": h["name"]}
                else:
                    r = identify_host(h["ip"], h["mac"], h["name"], ssdp.get(h["ip"]))
                h.update(r)
            except Exception:
                pass
            with disc_lock:
                disc["ident"] += 1
        with ThreadPoolExecutor(max_workers=12) as ex:
            list(ex.map(ident, hosts))
        with disc_lock:
            disc["hosts"] = hosts
    except Exception as e:
        with disc_lock:
            disc["err"] = str(e)[:150]
    finally:
        with disc_lock:
            disc["running"] = False
            disc["finished"] = time.time()


def discover_start(dev):
    if show_mode():
        return False
    with disc_lock:
        if disc["running"]:
            return False
        disc.update(running=True, ident=0, dev=dev, done=0, total=0, hosts=[], err=None, finished=None, started=time.time())
    threading.Thread(target=discover_run, args=(dev,), daemon=True).start()
    return True


def discover_clear():
    with disc_lock:
        if disc["running"]:
            return False
        disc.update(hosts=[], done=0, total=0, ident=0, err=None, finished=None)
    return True


def network_view(local=False):
    with disc_lock:
        d = dict(disc)
    with peers_lock:
        pl = [{"ip": p["ip"], "host": p.get("host", ""), "workspaces": p.get("workspaces", [])} for p in peers.values()]
    with config_lock:
        roles = dict(config["roles"])
    ifs = []
    for i in net_all():
        i = dict(i)
        i["mon"] = net_monitored(i["dev"])
        ifs.append(i)
    return {"ifaces": ifs, "discover": d, "now": time.time(), "local": local, "roles": roles, "mode": config.get("mode", "edit"), "peers": pl,
            "host": host_name(), "port": HTTP_PORT, "pings": dict(pings)}


NETWORK_PAGE = """<!doctype html>
<html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<title>Network</title>
<style>
  :root{--or:#ff8a00;--dim:#7a4300;--gr:#39ff88;--rd:#ff2d2d;--ye:#ffd60a}
  html{-webkit-text-size-adjust:100%}
  html,body{margin:0;background:#000;color:var(--or);font-family:"Endurance Sans","DejaVu Sans Condensed","Helvetica Neue",Arial,sans-serif}
  body{padding:env(safe-area-inset-top) 12px calc(env(safe-area-inset-bottom) + 24px);max-width:560px;margin:0 auto}
  /*FONT*/
  .serif{font-family:"Endurance Serif","Hiragino Mincho ProN","Yu Mincho",Georgia,"Times New Roman",serif;font-weight:900}
  .head{display:flex;align-items:center;justify-content:center;gap:12px;padding:12px 0 6px}
  .head svg{width:40px;height:40px;flex:none}
  .title{font-size:17px;line-height:1;letter-spacing:.06em;text-transform:uppercase}
  .tags{display:flex;flex-wrap:wrap;justify-content:center;gap:4px;margin:2px 0 8px}
  .tag{border:1px solid var(--or);padding:1px 5px;font-size:10px;letter-spacing:.06em;text-transform:uppercase;white-space:nowrap;color:var(--or);text-decoration:none;background:#000;font-family:inherit}
  .tag.on{color:var(--gr);border-color:var(--gr)}
  button.tag{cursor:pointer;font-size:11px;padding:3px 9px}
  button.tag.sm{font-size:9px;padding:1px 6px}
  button.tag:disabled{opacity:.4}
  select{background:#000;color:var(--or);border:1px solid var(--or);font:inherit;font-size:11px;padding:3px 4px;border-radius:0;max-width:100%}
  .sec{display:flex;align-items:center;gap:8px;margin:14px 0 6px;font-size:10px;letter-spacing:.2em;text-transform:uppercase}
  .sec i{flex:1;height:1px;background:var(--or);opacity:.45}
  .row{display:flex;justify-content:space-between;gap:8px;font-size:10px;letter-spacing:.04em;border-bottom:1px solid #2a1600;padding:4px 0;text-transform:uppercase}
  .row b{font-weight:700}
  .row span{color:var(--dim)}
  .row .l{flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;line-height:18px}
  .ctl{display:flex;gap:8px;align-items:center;justify-content:center;flex-wrap:wrap;margin:6px 0}
  .bar{height:4px;background:#1a0d00;margin:6px 0}.bar div{height:100%;background:var(--or);width:0}
  .empty{color:var(--dim);font-size:10px;padding:8px 0;text-transform:uppercase}
  .note{font-size:8px;line-height:1.5;letter-spacing:.04em;color:var(--dim);padding:4px 0}
  .rb{display:inline-block;vertical-align:middle;font-size:9px;line-height:12px;padding:0 4px;border:1px solid;margin-right:4px;letter-spacing:.08em}
  .rb.main{color:var(--gr);border-color:var(--gr)}
  .rb.backup{color:var(--ye);border-color:var(--ye)}
  .mm{border-bottom:1px solid #2a1600;padding:3px 0}
  .mm .row{border:0;padding:2px 0}
  .mb{display:flex;gap:4px;flex-wrap:wrap;align-items:center;padding:2px 0 3px}
  .pg{font-size:9px;letter-spacing:.04em;text-transform:uppercase}
  .credit{margin:22px 0 4px;font-size:5.5px;letter-spacing:.1em;text-transform:uppercase;color:var(--dim)}
</style></head><body>
<div class="head"><svg viewBox="0 0 40 40" fill="none" stroke="#ff8a00" stroke-width="1.5" stroke-linejoin="round"><circle cx="20" cy="20" r="18" stroke-width="1.3"/><g transform="translate(19.6 20.6) scale(0.032) translate(-600 -532)" stroke-linejoin="round" stroke-linecap="round" fill="none"><path d="M640 130 C705 130 760 150 790 178 L928 215 L800 258 L765 298 L730 322 C790 345 832 450 832 620 L830 800 L782 932 L470 932 L276 750 C275 600 330 420 440 330 C470 290 475 235 520 185 C560 148 600 130 640 130 Z" fill="#000" stroke="#000" stroke-width="75"/><path d="M640 130 C705 130 760 150 790 178 L928 215 L800 258 L765 298 L730 322 C790 345 832 450 832 620 L830 800 L782 932 L470 932 L276 750 C275 600 330 420 440 330 C470 290 475 235 520 185 C560 148 600 130 640 130 Z" stroke="#ff8a00" stroke-width="42.1875" fill="#000"/><path d="M725 328 C610 335 565 440 556 530 C552 620 570 650 566 700 L512 826 L428 862 L455 716 L405 590 C440 480 500 400 560 350 C610 316 670 318 725 328 Z" stroke="#ff8a00" stroke-width="42.1875"/><path d="M790 178 L742 218 L800 258 M742 226 L920 214" stroke="#ff8a00" stroke-width="42.1875"/></g></svg>
<div class="title serif">Network</div></div>
<div class="tags"><a class="tag" href="/">&lsaquo; The Endurance</a></div>
<div class="sec"><span>Host</span><i></i></div>
<div id="host"></div>
<div class="sec"><span>Main and backup machines</span><i></i></div>
<div class="note" id="rnote"></div>
<div id="machines"></div>
<div class="ctl"><button class="tag" id="pa">Ping all</button></div>
<div class="sec"><span>Wired connections</span><i></i></div>
<div id="wired"></div>
<div class="sec"><span>Wireless connections</span><i></i></div>
<div id="wifi"></div>
<div class="sec"><span>Other connections</span><i></i></div>
<div id="other"></div>
<div class="sec"><span>Network discover</span><i></i></div>
<div class="ctl"><select id="dev"></select><button class="tag" id="go">Start discovering</button><button class="tag" id="rf">Refresh</button><button class="tag" id="cl" style="color:#ff2d2d;border-color:#ff2d2d">Clear</button></div>
<div class="bar"><div id="pgb"></div></div>
<div class="empty" id="dst"></div>
<div id="hosts"></div>
<div class="credit serif">crafted by Francesco Lo Brano</div>
<script>
function esc(x){return String(x).replace(/[&<>"]/g,function(c){return{"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]})}
var lastDev="",sel="",lastOpts="",D=null,pingRes={},pinging={};
function startDisc(d){if(!d)return;fetch("/network/discover?dev="+encodeURIComponent(d),{method:"POST"}).then(tick).catch(function(){})}
document.getElementById("rf").onclick=function(){startDisc(lastDev||document.getElementById("dev").value)};
document.getElementById("cl").onclick=function(){fetch("/network/clear",{method:"POST"}).then(tick).catch(function(){})};
document.getElementById("dev").onchange=function(){sel=this.value};
document.getElementById("go").onclick=function(){var d=document.getElementById("dev").value;if(!d)return;startDisc(d)};
document.getElementById("pa").onclick=function(){pingAll()};
function roleOf(ip){return D&&D.roles?(D.roles[ip]||""):""}
function pgTxt(ip){
  if(pinging[ip])return '<span style="color:#ffd60a">pinging...</span>';
  var r=pingRes[ip],s=D&&D.pings&&D.pings[ip];
  if(!r||(s&&s.t>r.t))r=s;
  if(!r)return "";
  var age=D?Math.max(0,Math.round(D.now-r.t)):0;
  return r.ok?'<span style="color:#39ff88">ping ok &middot; '+(r.avg==null?"":r.avg+" ms &middot; ")+'loss '+r.loss+'% &middot; '+age+'s ago</span>'
             :'<span style="color:#ff2d2d">no answer &middot; loss '+r.loss+'% &middot; '+age+'s ago</span>';
}
function mrow(o){
  var r=roleOf(o.ip),loc=D&&D.local;
  var bd=r?'<b class="rb '+r+'">'+r+'</b>':'';
  var btn="";
  if(loc){
    btn+='<button class="tag sm'+(r==="main"?" on":"")+'" data-act="role" data-ip="'+esc(o.ip)+'" data-role="main">Main</button>'
       +'<button class="tag sm'+(r==="backup"?" on":"")+'" data-act="role" data-ip="'+esc(o.ip)+'" data-role="backup">Backup</button>'}
  if(o.ip!=="self")btn+='<button class="tag sm" data-act="ping" data-ip="'+esc(o.ip)+'">Ping</button>';
  return '<div class="mm"><div class="row"><b class="l" style="color:'+(o.me?"#39ff88":"#ff8a00")+'">'+bd+esc(o.name||"-")+'</b><span class="l" style="text-align:right;color:#ff8a00">'+esc(o.addr||"")+'</span></div>'
    +(o.info?'<div class="row"><span class="l">'+o.info+'</span></div>':'')
    +'<div class="mb">'+btn+'<span class="pg">'+(o.ip==="self"?"":pgTxt(o.ip))+'</span></div></div>';
}
function hostRow(){
  var ips=D.ifaces.filter(function(i){return i.ip&&i.mon!==false}).map(function(i){return esc(i.name)+" "+esc(i.ip)+":"+D.port}).join("<br>")||"no IP address";
  return mrow({ip:"self",me:true,name:D.host+" (this Mac)",addr:"",info:ips});
}
function machineList(){
  var m=[],seen={},d=D.discover;
  function add(o){if(o.ip&&!seen[o.ip]){seen[o.ip]=1;m.push(o)}}
  D.peers.forEach(function(p){add({ip:p.ip,name:p.host||"Mac",addr:p.ip,info:"QLab: "+esc(p.workspaces.join(" / ")||"---")})});
  (d.hosts||[]).forEach(function(h){if(roleOf(h.ip)&&!h.me)add({ip:h.ip,name:h.name||"-",addr:h.ip,info:esc(h.type||"")+(h.vendor?" &middot; "+esc(h.vendor):"")})});
  Object.keys(D.roles).forEach(function(ip){if(ip!=="self")add({ip:ip,name:"-",addr:ip,info:""})});
  m.sort(function(a,b){var ra=roleOf(a.ip)==="main"?0:roleOf(a.ip)==="backup"?1:2,rb=roleOf(b.ip)==="main"?0:roleOf(b.ip)==="backup"?1:2;return ra-rb});
  return m;
}
function allIps(){return machineList().map(function(x){return x.ip}).concat((D.discover.hosts||[]).filter(function(h){return !h.me}).map(function(h){return h.ip})).filter(function(v,i,a){return a.indexOf(v)===i})}
function doPing(ip,cb){
  if(pinging[ip]){if(cb)cb();return}
  pinging[ip]=1;draw();
  fetch("/ping?ip="+encodeURIComponent(ip),{cache:"no-store"}).then(function(r){return r.json()}).then(function(r){
    delete pinging[ip];pingRes[ip]=(r&&r.t)?r:{ok:false,loss:100,t:D?D.now:0};draw();if(cb)cb()}).catch(function(){delete pinging[ip];draw();if(cb)cb()});
}
function pingAll(){var ips=allIps();(function nx(i){if(i>=ips.length)return;doPing(ips[i],function(){nx(i+1)})})(0)}
document.body.addEventListener("click",function(e){
  var b=e.target&&e.target.closest?e.target.closest("[data-act]"):null;if(!b)return;
  var a=b.getAttribute("data-act"),ip=b.getAttribute("data-ip");
  if(a==="role"){var cur=roleOf(ip),want=b.getAttribute("data-role");
    fetch("/role?target="+encodeURIComponent(ip)+"&role="+(cur===want?"none":want),{method:"POST"}).then(tick).catch(function(){})}
  else if(a==="ping")doPing(ip);
});
function row(i){
  var up=i.status==="active"||(!i.status&&i.ip);
  var ipt=i.ip?esc(i.ip)+(i.prefix?"/"+i.prefix:""):(i.status==="inactive"?"no cable":"no ip");
  var l2=esc(i.dev);
  if(i.ip&&i.mode)l2+=' &middot; <b style="color:'+(i.mode==="MANUAL"?"#ffd60a":"#39ff88")+'">'+esc(i.mode)+'</b>';
  if(i.ip&&i.router)l2+=' &middot; gateway '+esc(i.router);
  if(i.mon===false)l2+=' &middot; <b style="color:#ffd60a">left alone</b>';
  var md=(i.media&&up)?esc(i.media.replace(/<.*>/,"").trim()):"";
  return '<div class="mm"><div class="row" style="border:0;padding-bottom:0"><b class="l" style="color:'+(up&&i.ip?"#39ff88":"#7a4300")+'">'+esc(i.name)+(i.enabled===false?" (disabled)":"")+'</b><span>'+ipt+'</span></div>'
    +'<div class="row" style="border:0;padding-top:0"><span style="white-space:normal">'+l2+'</span><span style="text-align:right;white-space:normal">'+md+'</span></div></div>';
}
function group(list,msg){return list.length?list.map(row).join(""):'<div class="empty">'+msg+'</div>'}
function draw(){
  if(!D)return;
  var d=D;
  document.getElementById("host").innerHTML=hostRow();
  document.getElementById("rnote").textContent=d.local?"Main = the machine running the show. Backup = the machine ready to take over. One of each; this Mac can be either. When the load rises, The Endurance tells you to prepare the switch to the backup.":"Main = the machine running the show. Backup = the machine ready to take over. Change them from the browser of the Mac itself or from the desktop app.";
  var ml=machineList();
  document.getElementById("machines").innerHTML=ml.length?ml.map(mrow).join(""):'<div class="empty">No other machine yet: QLab machines appear here by themselves; use Network discover to find any other machine</div>';
  document.getElementById("wired").innerHTML=group(d.ifaces.filter(function(i){return i.kind==="wired"}),"No wired connection");
  document.getElementById("wifi").innerHTML=group(d.ifaces.filter(function(i){return i.kind==="wifi"}),"No wireless connection");
  document.getElementById("other").innerHTML=group(d.ifaces.filter(function(i){return i.kind==="other"}),"None");
  var x=d.discover,pct=x.total?Math.round(x.done/x.total*100):0;
  document.getElementById("hosts").innerHTML=(x.hosts||[]).map(function(h){
    return mrow({ip:h.ip,me:h.me,name:h.name||"-",addr:h.ip,info:esc(h.type||(x.running?"":"unknown type"))+(h.vendor?" &middot; "+esc(h.vendor):"")+(h.mac?" &middot; "+esc(h.mac):"")+((h.ports&&h.ports.length)?" &middot; port "+h.ports.join(","):"")})}).join("");
}
function tick(){
  fetch("/networkdata",{cache:"no-store"}).then(function(r){return r.json()}).then(function(d){
    D=d;
    var opts=d.ifaces.filter(function(i){return i.ip&&i.mon!==false}).map(function(i){return '<option value="'+esc(i.dev)+'">'+esc(i.name)+' ('+esc(i.dev)+') '+esc(i.ip)+'</option>'}).join("");
    var s=document.getElementById("dev");
    if(opts!==lastOpts){lastOpts=opts;s.innerHTML=opts;if(sel)s.value=sel}
    var x=d.discover,pct=x.total?Math.round(x.done/x.total*100):0;
    document.getElementById("pgb").style.width=(x.running?pct:(x.finished?100:0))+"%";
    document.getElementById("go").disabled=x.running;document.getElementById("rf").disabled=x.running||!x.dev;document.getElementById("cl").disabled=x.running;if(x.dev)lastDev=x.dev;
    document.getElementById("dst").textContent=x.err?x.err:x.running?(x.total&&x.done>=x.total?"Identifying devices... "+x.ident+"/"+x.hosts.length:"Scanning "+x.dev+"... "+pct+"%"):x.finished?x.hosts.length+" machines found on "+x.dev:"Choose a connection and press start";
    draw();
  }).catch(function(){});
}
tick();setInterval(tick,2000);
</script></body></html>
"""


# ---- "Pull info": reads CPU, RAM, swap and DEFCON of another Mac running The Endurance; the other Mac sees who is watching it ----
pull_set = set()
pulled = {}
watchers = {}            # name of who is watching us -> last time
pull_lock = threading.Lock()


def _clean_name(n):
    return re.sub(r"[^\w .\-]", "", n or "")[:40].strip()


def pull_one(ip):
    import urllib.request
    try:
        req = urllib.request.Request("http://%s:%d/state" % (ip, HTTP_PORT), headers={"X-Endurance-From": host_name() or "Mac"})
        with urllib.request.urlopen(req, timeout=2) as r:
            d = json.loads(r.read(200000).decode("utf-8", "replace"))
        y, df = d.get("sys") or {}, d.get("defcon") or {}
        if "sys" not in d:
            raise ValueError("not endurance")
        rec = {"ok": True, "cpu": y.get("cpu"), "ram": y.get("ram"), "swap": y.get("swap"), "pr": y.get("pressure"),
               "lv": df.get("level"), "ver": d.get("version"), "t": time.time()}
    except Exception:
        rec = {"ok": False, "t": time.time()}
    with pull_lock:
        if ip in pull_set:
            pulled[ip] = rec


def pull_loop():
    while True:
        with pull_lock:
            ips = [i for i in pull_set if not ip_excluded(i)]
        if ips:
            with ThreadPoolExecutor(max_workers=6) as ex:
                list(ex.map(pull_one, ips))
        time.sleep(3.0)


def pull_set_ip(ip, on):
    try:
        a = ipaddress.IPv4Address(ip)
    except ValueError:
        return False
    if not (a.is_private or a.is_link_local) or ip_excluded(ip):
        return False
    ip = str(a)
    with pull_lock:
        if on:
            pull_set.add(ip)
        else:
            pull_set.discard(ip)
            pulled.pop(ip, None)
    if on:
        threading.Thread(target=pull_one, args=(ip,), daemon=True).start()
    return True


# ---- Key app in details, backup QLab cues, Call, QLab main -> backup sync ----
KEYAPPS = [("QLab", ["qlab"]), ("Keynote", ["keynote"]), ("PowerPoint", ["powerpoint"]), ("Ableton Live", ["abletonlive", "ableton"]),
           ("Reaper", ["reaper"]), ("Pro Tools", ["protools"]), ("Smaart", ["smaart"]), ("Arena", ["resolumearena", "arena"]),
           ("Live Professor", ["liveprofessor"]), ("Wireless Workbench", ["workbench"]), ("Compass", ["compass"]), ("R1", ["r1", "dbr1"]),
           ("Millumin", ["millumin"]), ("vMix", ["vmix"])]
APP_LABELS = {"DVS_APE": ("Dante Virtual Soundcard", 5.0)}      # process -> (readable name, % of a core below which it is not shown)
KEY_STABLE = ("QLab", "Keynote", "Reaper", "Smaart", "PowerPoint", "Live Professor")      # the other key apps are (beta)
REMOTE_OK = ("vMix", "PowerPoint", "Arena", "Smaart", "Live Professor")      # they can run on another computer: they are read even when they are not running on this Mac
KD_DEFAULT = {"fmt": "time", "pp_port": 35550, "reaper_port": 9001, "arena": "127.0.0.1:8081", "vmix": "", "ableton": "127.0.0.1:11000", "smaart": "localhost:26000", "lp": "127.0.0.1:8000", "lp_out": 9000}
KD_KEYS = {"fmt": r"time|bars", "pp_port": r"\d{4,5}", "reaper_port": r"\d{4,5}", "arena": r"[0-9.]{7,15}:\d{2,5}|", "vmix": r"[0-9.]{7,15}(:\d{2,5})?|",
           "ableton": r"[0-9.]{7,15}(:\d{2,5})?", "smaart": r"[0-9A-Za-z.\-]{1,60}(:\d{2,5})?", "lp": r"[0-9.]{7,15}(:\d{2,5})?", "lp_out": r"\d{4,5}"}


def key_canon(name):
    n = _norm(name)
    for lab, pats in KEYAPPS:
        if _norm(lab) == n:
            return lab
    for lab, pats in KEYAPPS:
        if any(n == p or (len(p) >= 3 and p in n) for p in pats):
            return lab
    return None


def key_pats(key):
    lab = key_canon(key)
    for l, pats in KEYAPPS:
        if l == lab:
            return pats
    k = _norm(key)
    return [k] if k else []


def kd_get(k):
    v = (config.get("kd") or {}).get(k)
    return KD_DEFAULT.get(k, "") if (v is None or (v == "" and k != "vmix")) else v


def kd_set(k, v):
    v = str(v).strip()
    if k not in KD_KEYS or not re.fullmatch(KD_KEYS[k], v):
        return False
    if (k.endswith("_port") or k == "lp_out") and not (1024 <= int(v) <= 65535):
        return False
    if ":" in v and not (1 <= int(v.rsplit(":", 1)[1]) <= 65535):
        return False
    with config_lock:
        config.setdefault("kd", {})[k] = int(v) if k.endswith("_port") else v
    config_save()
    kd_wake.set()
    return True


def _hp(s, default):
    h, _, p = str(s).partition(":")
    try:
        return h, int(p) if p else default
    except ValueError:
        return h, default


# ---- QLab on the backup Mac (or on the main, if this Mac is the backup): read-only active cues ----
bk = {"ip": "", "role": "", "online": False, "reply": 0.0, "order": [], "cues": {}, "ts": {}, "wsid": None, "wsn": {}}
bk_lock = threading.Lock()


def other_mac():
    with config_lock:
        roles = dict(config["roles"])
    want = "main" if roles.get("self") == "backup" else "backup"
    return next((k for k, v in roles.items() if v == want and k != "self"), None), want


def _bk_reset(ip, role):
    with bk_lock:
        bk.update(ip=ip or "", role=role, online=False, reply=0.0, order=[], cues={}, ts={}, wsid=None, wsn={})


def _sendc(c, address, *args):
    c.sendall(slip_encode(osc_encode(address, *args)))


def _bk_packet(buf):
    try:
        address, args = osc_decode(buf)
        reply = json.loads(args[0])
    except Exception:
        return
    data = reply.get("data")
    with bk_lock:
        bk["reply"] = time.time()
        if reply.get("workspace_id"):
            bk["wsid"] = reply["workspace_id"]
        if address.endswith("/workspaces") and isinstance(data, list):
            bk["wsn"] = {w["uniqueID"]: (w.get("displayName") or "") for w in data if isinstance(w, dict) and w.get("uniqueID")}
        elif address.endswith("/runningCues") and isinstance(data, list):
            ids = [c["uniqueID"] for c in data if isinstance(c, dict) and "uniqueID" in c]
            bk["order"] = ids
            for u in [u for u in bk["cues"] if u not in ids]:
                del bk["cues"][u]
        elif "/cue_id/" in address and address.endswith("/valuesForKeys"):
            uid = address.split("/cue_id/")[1].split("/")[0]
            if uid in bk["order"] and isinstance(data, dict):
                bk["cues"][uid] = data
                bk["ts"][uid] = time.time()


def bk_loop():
    """Second OSC (TCP) connection to the other Mac's QLab, read-only: /runningCues and the values of the active cues.
    Slow readings (1.5 s) when there are no active cues, 0.5 s when there are. No traffic on unselected ports."""
    keys = json.dumps(["listName", "number", "actionElapsed", "duration", "percentActionElapsed", "infiniteLoop", "playCount", "isPaused", "preWait", "preWaitElapsed", "currentDuration"])
    while True:
        ip, role = other_mac()
        if not ip or ip_excluded(ip):
            _bk_reset(ip, role)
            time.sleep(2.0)
            continue
        _bk_reset(ip, role)
        try:
            c = socket.create_connection((ip, QLAB_PORT), timeout=2)
            c.settimeout(0.5)
            if PASSCODE:
                _sendc(c, "/connect", PASSCODE)
            _sendc(c, "/updates", 0)
            _sendc(c, "/workspaces")
        except OSError:
            time.sleep(3.0)
            continue
        buf, last, n = b"", 0.0, 0
        try:
            while True:
                now = time.time()
                if other_mac()[0] != ip or ip_excluded(ip):
                    break
                with bk_lock:
                    ids = list(bk["order"])
                if now - last >= (0.5 if ids else 1.5):
                    last = now
                    if n % 8 == 0:
                        _sendc(c, "/workspaces")
                    n += 1
                    _sendc(c, "/runningCues")
                    for u in ids:
                        _sendc(c, "/cue_id/%s/valuesForKeys" % u, keys)
                try:
                    chunk = c.recv(65536)
                except socket.timeout:
                    chunk = None
                if chunk == b"":
                    break
                if chunk:
                    frames, buf = slip_frames(buf + chunk)
                    for f in frames:
                        _bk_packet(f)
                with bk_lock:
                    rp = bk["reply"]
                if rp and now - rp > 8:
                    break
        except OSError:
            pass
        finally:
            try:
                c.close()
            except OSError:
                pass
            _bk_reset(ip, role)
        time.sleep(2.0)


def bk_view():
    ip, role = other_mac()
    if not ip:
        return None, []
    now = time.time()
    out = []
    with bk_lock:
        online = bool(bk["reply"]) and now - bk["reply"] < 5 and bk["ip"] == ip
        for uid in bk["order"]:
            c = bk["cues"].get(uid)
            if not c:
                continue
            t = cue_timer(uid, c, now)
            if not t["paused"]:
                dt = min(max(now - bk["ts"].get(uid, now), 0.0), 0.8)
                t["elapsed"] = min(t["elapsed"] + dt, t["duration"]) if t["duration"] > 0 else t["elapsed"] + dt
            out.append({"id": uid, "name": c.get("listName") or "(no name)", "number": c.get("number", ""), "elapsed": t["elapsed"], "duration": t["duration"],
                        "loop": t["loop"], "pre": t["pre"], "paused": t["paused"]})
        ws = bk["wsn"].get(bk["wsid"]) or (next(iter(bk["wsn"].values())) if len(bk["wsn"]) == 1 else "")
    return {"ip": ip, "role": role, "host": mac_name(ip), "online": online, "workspace": ws}, out


# ---- Call: calls another Mac (green hexagon on its browser page) ----
calls = []                   # [{"id", "ip", "name", "role", "t"}]
calls_lock = threading.Lock()
call_rate = {}
call_seq = [0]


def call_send(ip):
    import urllib.request
    from urllib.parse import quote
    try:
        a = ipaddress.IPv4Address(ip)
    except ValueError:
        return False
    if not _valid_ip(str(a)) or ip_excluded(str(a)):
        return False
    ip = str(a)
    now = time.time()
    if now - call_rate.get(("out", ip), 0) < 2.0:
        return False
    call_rate[("out", ip)] = now
    with config_lock:
        me = config["roles"].get("self", "")
    url = "http://%s:%d/callin?name=%s&role=%s" % (ip, HTTP_PORT, quote(_clean_name(host_name() or "Mac")), me)
    try:
        req = urllib.request.Request(url, data=b"", method="POST", headers={"X-Endurance-From": host_name() or "Mac"})
        with urllib.request.urlopen(req, timeout=3) as r:
            return r.read(10) == b"ok"
    except Exception:
        return False


def call_in(client_ip, name, role):
    try:
        a = ipaddress.IPv4Address(client_ip)
    except ValueError:
        return False
    if not (a.is_private and not a.is_loopback) or ip_excluded(client_ip):
        return False
    now = time.time()
    if now - call_rate.get(("in", client_ip), 0) < 3.0:
        return False
    call_rate[("in", client_ip)] = now
    with calls_lock:
        calls[:] = [c for c in calls if now - c["t"] < 3600]
        if len(calls) >= 6:
            del calls[0]
        call_seq[0] += 1
        calls.append({"id": call_seq[0], "ip": client_ip, "name": _clean_name(name)[:30] or "Mac", "role": role if role in ("main", "backup") else "", "t": now})
    return True


def call_dismiss(cid):
    with calls_lock:
        calls[:] = [c for c in calls if str(c["id"]) != str(cid)] if cid != "all" else []
    return True


# ---- Key app in details ----
kd = {"app": "", "d": None, "err": "", "t": 0.0}
kd_lock = threading.Lock()
kd_wake = threading.Event()
kd_udp = {}                      # (app, indirizzo) -> socket
kd_udp_stop = threading.Event()
kd_in = {}                       # dati ricevuti via OSC/UDP: chiave -> (valore, istante)


def _kd_set(app, d, err=""):
    with kd_lock:
        kd.update(app=app, d=d, err=err, t=time.time())


def _kd_http(url, timeout=1.5, limit=400000):
    import urllib.request
    with urllib.request.urlopen(url, timeout=timeout) as r:
        return r.read(limit)


def kd_keynote():
    scr = ('tell application "Keynote"\nif (count of documents) is 0 then return "none"\nset d to front document\n'
           'return (name of d) & "\\t" & (slide number of current slide of d) & "\\t" & (count of slides of d)\nend tell')
    out = subprocess.check_output(["osascript", "-e", scr], text=True, timeout=4, env=ENV).strip()
    if out == "none":
        return {"kind": "keynote", "doc": "", "slide": 0, "total": 0}
    n, s, t = out.rsplit("\t", 2)
    return {"kind": "keynote", "doc": n, "slide": int(s), "total": int(t)}


def kd_arena():
    h, p = _hp(kd_get("arena"), 8081)
    if p == HTTP_PORT and h in ("127.0.0.1", "localhost"):
        raise ValueError("Port %d is used by The Endurance: change the Resolume web server port (Preferences > Webserver) and set it here" % p)
    d = json.loads(_kd_http("http://%s:%d/api/v1/composition" % (h, p)).decode("utf-8", "replace"))

    def val(x):
        return x.get("value") if isinstance(x, dict) else x
    cues = []
    for li, lay in enumerate(d.get("layers") or []):
        for clip in lay.get("clips") or []:
            conn = str(val(clip.get("connected")) or "").lower()
            if "connected" not in conn or "disconnected" in conn:
                continue
            tr = clip.get("transport") or {}
            pos = tr.get("position") or {}
            mx = _num(pos.get("max"))
            cur = _num(pos.get("value"))
            el = cur if mx > 1.5 else cur * _num(val((clip.get("video") or {}).get("duration")) or 0)
            cues.append({"id": "%s/%s" % (li, clip.get("id", "")), "name": str(val(clip.get("name")) or "clip"), "number": "L%d" % (li + 1),
                         "elapsed": el, "duration": mx if mx > 1.5 else 0, "loop": False, "pre": False, "paused": False})
    return {"kind": "cues", "ws": str(val(d.get("name")) or ""), "cues": cues}


def kd_vmix():
    h, p = _hp(kd_get("vmix"), 8088)
    if not h:
        raise ValueError("Set the vMix IP address (vMix runs on Windows)")
    import xml.etree.ElementTree as ET
    root = ET.fromstring(_kd_http("http://%s:%d/api" % (h, p)))
    act = (root.findtext("active") or "").strip()
    cues = []
    for i in root.iter("input"):
        if i.get("number") == act:
            dur, pos = _num(i.get("duration")) / 1000.0, _num(i.get("position")) / 1000.0
            cues.append({"id": act, "name": i.get("title") or i.text or "input", "number": act, "elapsed": pos, "duration": dur,
                         "loop": i.get("loop") == "True", "pre": False, "paused": i.get("state") == "Paused"})
    return {"kind": "cues", "ws": (root.findtext("version") and "vMix " + root.findtext("version")) or "vMix", "cues": cues}


udp_err = {}


def _udp_open(app, port):
    want = {a for a in bind_wanted()}
    if "0.0.0.0" in want:
        want = {"0.0.0.0"}
    for k in [k for k in kd_udp if k[0] != app or k[1] not in want or k[2] != port]:
        try:
            kd_udp.pop(k).close()
        except OSError:
            pass
    for a in want:
        if (app, a, port) in kd_udp:
            continue
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((a, port))
            s.settimeout(1.0)
        except OSError as e:
            udp_err[app] = "UDP port %d could not be opened on %s: %s" % (port, a, e.strerror or e)
            continue
        udp_err.pop(app, None)
        kd_udp[(app, a, port)] = s
        threading.Thread(target=_udp_reader, args=(app, a, port, s), daemon=True).start()
    return bool(kd_udp)


def _osc_msgs(buf, depth=0):
    """OSC messages of a datagram, also inside bundles (Reaper and OSCPoint can pack them)."""
    out = []
    try:
        if buf.startswith(b"#bundle"):
            if depth > 4:
                return out
            i = 16
            while i + 4 <= len(buf):
                n = struct.unpack(">I", buf[i:i + 4])[0]
                i += 4
                out += _osc_msgs(buf[i:i + n], depth + 1)
                i += n
        else:
            out.append(osc_decode(buf))
    except Exception:
        pass
    return out


def _udp_close_all():
    for k in list(kd_udp):
        try:
            kd_udp.pop(k).close()
        except OSError:
            pass


def _udp_reader(app, a, port, s):
    while (app, a, port) in kd_udp and kd_udp.get((app, a, port)) is s:
        try:
            buf, src = s.recvfrom(65535)
        except socket.timeout:
            continue
        except OSError:
            break
        if ip_excluded(src[0]) and src[0] != "127.0.0.1":
            continue
        msgs = _osc_msgs(buf)
        now = time.time()
        for address, args in msgs:
            if args:
                if len(kd_in) > 400:      # a sender that invents OSC addresses must not make memory grow
                    kd_in.clear()
                kd_in[(app, address.lower())] = (args[0], now)


def _in(app, suffix):
    for (a, ad), (v, t) in list(kd_in.items()):
        if a == app and ad.endswith(suffix):
            return v, t
    return None, 0.0


def _ppt_osc():
    """OSCPoint data (PowerPoint add-in, Windows): only needed for the video time."""
    st, t0 = _in("powerpoint", "/media/state")
    pos, t1 = _in("powerpoint", "/media/position")
    rem, t2 = _in("powerpoint", "/media/remaining")
    dur, t3 = _in("powerpoint", "/media/duration")
    nm, t4 = _in("powerpoint", "/presentation/name")
    cnt, t5 = _in("powerpoint", "/presentation/slides/count")
    cur, t6 = _in("powerpoint", "/slideshow/currentslide")
    last = max(t0, t1, t2, t3, t4, t5, t6)
    d = {"osc_seen": last}
    if nm is not None:
        d["osc_doc"] = str(nm)
    if cnt is not None:
        d["osc_total"] = int(_num(cnt))
    if cur is not None:
        d["osc_slide"] = int(_num(cur))
    if t1 and time.time() - t1 < 4:                 # the video is playing (OSCPoint sends data every 500 ms)
        d.update(state=str(st) if st is not None else "", pos=_num(pos) / 1000.0 if pos is not None else None,
                 rem=_num(rem) / 1000.0 if rem is not None else None, dur=_num(dur) / 1000.0 if dur is not None else None, t=t1)
    return d


_pp = {"t": 0.0, "d": None}


def kd_powerpoint(running):
    """Presentation name and slide: from PowerPoint itself (AppleScript, if it runs on this Mac), without any add-in.
    The video time comes from OSCPoint (UDP), if present."""
    port = int(kd_get("pp_port"))
    _udp_open("powerpoint", port)
    d = {"kind": "ppt", "port": port, "doc": "", "slide": 0, "total": 0, "err": ""}
    if running:
        if time.time() - _pp["t"] >= 1.9 or _pp["d"] is None:
            scr = ('tell application "Microsoft PowerPoint"\nif (count of presentations) is 0 then return "none"\nset p to active presentation\n'
                   'set n to name of p\nset tot to count of slides of p\nset cur to 0\n'
                   'try\nif (count of slide show windows) > 0 then set cur to current show position of slide show view of slide show window 1\nend try\n'
                   'if cur is 0 then\ntry\nset cur to slide index of slide of view of active window\nend try\nend if\n'
                   'return n & tab & cur & tab & tot\nend tell')
            try:
                out = subprocess.check_output(["osascript", "-e", scr], text=True, timeout=5, env=ENV).strip()
                if out == "none":
                    _pp["d"] = {"doc": "", "slide": 0, "total": 0, "err": ""}
                else:
                    n, c, t = out.rsplit("\t", 2)
                    _pp["d"] = {"doc": n, "slide": int(c), "total": int(t), "err": ""}
            except Exception as e:
                _pp["d"] = {"doc": "", "slide": 0, "total": 0, "err": "Cannot read PowerPoint (allow The Endurance to control it in Privacy & Security > Automation)"}
            _pp["t"] = time.time()
        d.update(_pp["d"])
    d.update(_ppt_osc())
    if not d.get("doc") and d.get("osc_doc"):
        d.update(doc=d["osc_doc"], slide=d.get("osc_slide", 0), total=d.get("osc_total", 0))
    elif d.get("osc_slide") and not d.get("slide"):
        d.update(slide=d["osc_slide"], total=d.get("osc_total") or d["total"])
    return d


def _reaper_data():
    rec, tr = _in("reaper", "/record")
    play, tp = _in("reaper", "/play")
    tm, tt = _in("reaper", "/time")
    bs, tb = _in("reaper", "/beat/str")
    last = max(tr, tp, tt, tb)
    d = {"kind": "transport", "src": "Reaper", "port": int(kd_get("reaper_port")), "seen": last}
    if last:                                          # the last state received stays valid until Reaper sends another
        d.update(rec=bool(_num(rec)) if rec is not None else False, play=bool(_num(play)) if play is not None else False,
                 pos=_num(tm) if tm is not None else None, bars=str(bs).split(".")[:2] if bs else None, t=max(tt, tb) or last)
    return d


def kd_reaper():
    _udp_open("reaper", int(kd_get("reaper_port")))
    if "reaper" in udp_err and not any(k[0] == "reaper" for k in kd_udp):
        raise ValueError(udp_err["reaper"])
    return _reaper_data()


# ---- Smaart (Rational Acoustics): SPL level from the web viewer / API (JSON WebSocket, like Smaart's SPL page) ----
class MiniWS:
    """Minimal WebSocket client (text only), with the standard library."""

    def __init__(self, host, port, path, timeout=3.0):
        import base64
        if host in ("127.0.0.1", ""):
            host = "localhost"      # Smaart accepts the API only on the name "localhost" (not on 127.0.0.1)
        self.s = socket.create_connection((host, port), timeout=timeout)
        key = base64.b64encode(os.urandom(16)).decode()
        self.s.sendall(("GET %s HTTP/1.1\r\nHost: %s:%d\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: %s\r\n"
                        "Sec-WebSocket-Version: 13\r\nOrigin: http://%s:%d\r\n\r\n" % (path, host, port, key, host, port)).encode())
        buf = b""
        while b"\r\n\r\n" not in buf:
            ch = self.s.recv(4096)
            if not ch:
                raise OSError("connection closed")
            buf += ch
            if len(buf) > 65536:
                raise OSError("bad handshake")
        head, _, self.buf = buf.partition(b"\r\n\r\n")
        if b" 101 " not in head.split(b"\r\n")[0] + b" ":
            raise OSError("WebSocket refused: " + head.split(b"\r\n")[0].decode("latin-1", "replace")[:60])

    def close(self):
        try:
            self.s.close()
        except OSError:
            pass

    def send(self, text):
        data = text.encode("utf-8")
        n = len(data)
        hdr = bytearray([0x81])
        if n < 126:
            hdr.append(0x80 | n)
        elif n < 65536:
            hdr += bytes([0x80 | 126]) + struct.pack(">H", n)
        else:
            hdr += bytes([0x80 | 127]) + struct.pack(">Q", n)
        mask = os.urandom(4)
        self.s.sendall(bytes(hdr) + mask + bytes(b ^ mask[i % 4] for i, b in enumerate(data)))

    def _need(self, n, deadline):
        while len(self.buf) < n:
            left = deadline - time.time()
            if left <= 0:
                raise socket.timeout()
            self.s.settimeout(left)
            ch = self.s.recv(65536)
            if not ch:
                raise OSError("connection closed")
            self.buf += ch

    def recv(self, timeout=1.0):
        """One text message (None if nothing arrives within the timeout)."""
        deadline = time.time() + timeout
        out = b""
        while True:
            try:
                self._need(2, deadline)
            except socket.timeout:
                return None
            b0, b1 = self.buf[0], self.buf[1]
            ln, off = b1 & 0x7F, 2
            try:
                if ln == 126:
                    self._need(4, deadline + 2)
                    ln, off = struct.unpack(">H", self.buf[2:4])[0], 4
                elif ln == 127:
                    self._need(10, deadline + 2)
                    ln, off = struct.unpack(">Q", self.buf[2:10])[0], 10
                if ln > 4000000:
                    raise OSError("frame too large")
                self._need(off + ln, deadline + 2)
            except socket.timeout:
                return None
            payload, self.buf = self.buf[off:off + ln], self.buf[off + ln:]
            op = b0 & 0x0F
            if op == 8:
                raise OSError("closed by Smaart")
            if op == 9:
                self.s.sendall(bytes([0x8A, 0x80]) + os.urandom(4))
                continue
            if op == 10:
                continue
            out += payload
            if b0 & 0x80:
                return out.decode("utf-8", "replace")


sm = {"chs": [], "n_inputs": 0, "err": ""}
sm_lock = threading.Lock()
SM_ORDER = ["SPL A Slow", "SPL C Slow", "SPL A Fast", "SPL C Fast", "SPL Slow", "SPL Fast", "LAeq 1", "LAeq 10", "Peak C"]
SM_MAX = 6


def _sm_set(**kw):
    with sm_lock:
        sm.update(kw)


def _sm_inputs(host, port):
    """Calibrated inputs with logging active: [(device, channel, endpoint)]."""
    api = MiniWS(host, port, "/api/v4/")
    try:
        api.send('{"action":"get"}')
        r = json.loads(api.recv(4) or "{}").get("response") or {}
        if r.get("authenticationRequired"):
            raise ValueError("Smaart API needs a password: switch it off in Smaart (Options > Preferences > API)")
        api.send('{"action":"get","target":"activeCalibratedInputs"}')
        r = json.loads(api.recv(4) or "{}").get("response") or {}
        return [(d.get("deviceName", ""), c.get("channelName", ""), c.get("streamEndpoint", ""))
                for d in r.get("devices") or [] for c in d.get("activeCalibratedChannels") or [] if c.get("streamEndpoint")][:SM_MAX]
    finally:
        api.close()


def _sm_worker(host, port, i, ep, stop, errs):
    st = None
    try:
        st = MiniWS(host, port, ep)
        st.send('{"action":"set","properties":[{"targetFPS":2}]}')
        while not stop.is_set():
            msg = st.recv(1.0)
            if msg is None:
                with sm_lock:
                    t = sm["chs"][i]["t"] if i < len(sm["chs"]) else 0.0
                if t and time.time() - t > 15:
                    raise OSError("no data from Smaart")
                continue
            try:
                ms_ = json.loads(msg).get("metrics") or []
            except ValueError:
                continue
            vals, viol = {}, False
            for m in ms_:
                if isinstance(m, dict) and m:
                    k0 = next(iter(m))
                    if isinstance(m[k0], (int, float)):
                        vals[k0] = float(m[k0])
                    viol = viol or bool(m.get("violation"))
            if vals:
                with sm_lock:
                    if i < len(sm["chs"]):
                        sm["chs"][i].update(metrics=vals, t=time.time(), viol=viol)
    except (OSError, ValueError) as e:
        errs.append(str(e)[:140])
        stop.set()
    finally:
        if st:
            st.close()


def smaart_session(host, port):
    ins = _sm_inputs(host, port)
    if not ins:
        raise ValueError("No logging input in Smaart: SPL values exist only while logging is on (calibrated inputs)")
    _sm_set(n_inputs=len(ins), err="", chs=[{"name": "%s : %s" % (a, b), "metrics": {}, "t": 0.0, "viol": False} for a, b, _ in ins])
    stop, errs = threading.Event(), []
    ths = [threading.Thread(target=_sm_worker, args=(host, port, i, ep, stop, errs), daemon=True) for i, (_, _, ep) in enumerate(ins)]
    for t in ths:
        t.start()
    last = time.time()
    try:
        while not stop.is_set():
            time.sleep(0.5)
            if key_canon(config.get("key_app") or "") != "Smaart":
                _sm_set(chs=[], err="")
                return
            if time.time() - last > 5:
                last = time.time()
                if [e for _, _, e in _sm_inputs(host, port)] != [e for _, _, e in ins]:
                    return      # an input was switched on or off: start again
        raise OSError(errs[0] if errs else "closed by Smaart")
    finally:
        stop.set()


def smaart_loop():
    """A thread that only works when the key app is Smaart: one WebSocket for each calibrated input that is logging (2 updates per second)."""
    while True:
        if key_canon(config.get("key_app") or "") != "Smaart":
            _sm_set(chs=[], err="")
            time.sleep(2.0)
            continue
        h, p = _hp(kd_get("smaart"), 26000)
        try:
            if h not in ("127.0.0.1", "localhost") and ip_excluded(h):
                raise ValueError("The network port of this address is not monitored")
            smaart_session(h or "127.0.0.1", p)
        except (OSError, ValueError) as e:
            _sm_set(err=str(e)[:140], chs=[])
        time.sleep(3.0)


def _smaart_view():
    with sm_lock:
        chs = [dict(c, metrics=dict(c["metrics"])) for c in sm["chs"]]
        err = sm["err"]
    now = time.time()
    for c in chs:
        c["fresh"] = bool(c["t"]) and now - c["t"] < 5
        c["order"] = [k for k in SM_ORDER if k in c["metrics"]] + [k for k in c["metrics"] if k not in SM_ORDER and k != "FS Peak"][:2]
    return {"kind": "smaart", "err": err, "chs": chs, "fresh": any(c["fresh"] for c in chs)}


_lp = {"sock": None, "v": None, "t": 0.0, "port": 0}


def _lp_close():
    if _lp["sock"] is not None:
        try:
            _lp["sock"].close()
        except OSError:
            pass
        _lp["sock"] = None
        _lp["port"] = 0


def kd_liveprof():
    """LiveProfessor (Audiostrom): DSP load via OSC. In LiveProfessor: Options > Project Options > Osc Control, input port = the one in the field, output port = lp_out."""
    h, p = _hp(kd_get("lp"), 8000)
    op = int(kd_get("lp_out"))
    local = h in ("127.0.0.1", "localhost")
    if not local and ip_excluded(h):
        raise ValueError("Port of this address is not monitored")
    if _lp["sock"] is not None and _lp["port"] != op:
        _lp_close()
    s = _lp["sock"]
    if s is None:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("127.0.0.1" if local else "0.0.0.0", op))
        s.settimeout(0.15)
        _lp["sock"], _lp["port"] = s, op
    s.sendto(osc_encode("/StatusPoll"), (h or "127.0.0.1", p))
    end = time.time() + 0.4
    while time.time() < end:
        try:
            buf, _ = s.recvfrom(65535)
        except (socket.timeout, OSError):
            break
        for address, args in _osc_msgs(buf):
            if address.endswith("DSPmeter") and args and isinstance(args[-1], (int, float)):
                _lp["v"], _lp["t"] = float(args[-1]), time.time()
    d = {"kind": "dsp", "src": "LiveProfessor", "inp": p, "out": op, "t": _lp["t"]}
    if _lp["v"] is not None and time.time() - _lp["t"] < 5:
        v = _lp["v"]
        d["pct"] = v * 100.0 if v <= 1.0 else v
    return d


lpx = {"d": None}


def lpx_view():
    return dict(lpx["d"]) if (config.get("lp_extra") and lpx["d"]) else None


_ab = {"sock": None, "v": {}}


def kd_ableton():
    h, p = _hp(kd_get("ableton"), 11000)
    if h not in ("127.0.0.1", "localhost") and ip_excluded(h):
        raise ValueError("Port of this address is not monitored")
    s = _ab["sock"]
    if s is None:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("127.0.0.1", 11001))
        s.settimeout(0.15)
        _ab["sock"] = s
    for q in ("is_playing", "record_mode", "session_record", "current_song_time", "signature_numerator", "tempo"):
        s.sendto(osc_encode("/live/song/get/" + q), (h, p))
    end = time.time() + 0.3
    got = 0
    while time.time() < end and got < 6:
        try:
            buf, _ = s.recvfrom(65535)
            address, args = osc_decode(buf)
            if args:
                _ab["v"][address.rsplit("/", 1)[-1]] = (args[-1], time.time())
                got += 1
        except socket.timeout:
            break
        except Exception:
            break
    v = {k: x[0] for k, x in _ab["v"].items()}
    seen = max([x[1] for x in _ab["v"].values()] or [0])
    d = {"kind": "transport", "src": "Ableton Live", "port": p, "seen": seen}
    if seen and time.time() - seen < 5:
        beats = _num(v.get("current_song_time"))
        num = max(1, int(_num(v.get("signature_numerator"), 4)))
        tempo = _num(v.get("tempo"), 120) or 120
        d.update(rec=bool(_num(v.get("record_mode"))) or bool(_num(v.get("session_record"))), play=bool(_num(v.get("is_playing"))),
                 pos=beats * 60.0 / tempo, bars=[str(int(beats // num) + 1), str(int(beats % num) + 1)], t=seen)
    return d


def kd_loop():
    """Key app details reader: a single thread, active only while the key app is running. Slow readings."""
    while True:
        key = key_canon(config.get("key_app") or "") or ""
        ky = stats.get("key") or {}
        running = bool(ky.get("running"))
        d, err = None, ""
        if (not running and key not in REMOTE_OK) or key in ("", "QLab"):
            if key != "Ableton Live" and _ab["sock"] is not None:
                try:
                    _ab["sock"].close()
                except OSError:
                    pass
                _ab["sock"] = None
            if config.get("lp_extra") and key == "QLab":
                try:
                    lpx["d"] = kd_liveprof()
                except Exception as e:
                    lpx["d"] = {"kind": "dsp", "err": str(e)[:100]}
            else:
                _lp_close()
                lpx["d"] = None
            _udp_close_all()
            _kd_set(key, None)
            kd_wake.wait(1.0 if config.get("lp_extra") else 2.0)
            kd_wake.clear()
            continue
        try:
            if key == "Keynote":
                d = kd_keynote()
            elif key == "Arena":
                d = kd_arena()
            elif key == "vMix":
                d = kd_vmix()
            elif key == "PowerPoint":
                d = kd_powerpoint(running)
            elif key == "Reaper":
                d = kd_reaper()
            elif key == "Ableton Live":
                d = kd_ableton()
            elif key == "Smaart":
                d = _smaart_view()
            elif key == "Live Professor":
                d = kd_liveprof()
            else:
                d = {"kind": "none"}
        except Exception as e:
            err = str(e)[:160]
        if key != "Live Professor":
            _lp_close()
        if key not in ("PowerPoint", "Reaper"):
            _udp_close_all()
        _kd_set(key, d, err)
        kd_wake.wait(0.5 if key in ("Ableton Live",) else 1.0 if key == "Live Professor" else 2.0)
        kd_wake.clear()


def kd_view():
    with kd_lock:
        key, d, err, t = kd["app"], kd["d"], kd["err"], kd["t"]
    out = {"app": key, "err": err, "d": None}
    if not d:
        return out
    d = dict(d)
    now = time.time()
    if d.get("kind") == "cues":
        cs = []
        for c in d["cues"]:
            c = dict(c)
            if not c["paused"] and c["duration"] > 0:
                c["elapsed"] = min(c["elapsed"] + min(max(now - t, 0), 2.0), c["duration"])
            cs.append(c)
        d["cues"] = cs
    elif d.get("kind") == "smaart":
        d = _smaart_view()
    elif d.get("kind") == "ppt":
        for k in ("state", "pos", "rem", "dur", "t"):
            d.pop(k, None)
        d.update(_ppt_osc())
        if d.get("rem") is not None:
            d["rem"] = max(0.0, d["rem"] - min(max(now - d.get("t", now), 0), 1.0))
    elif d.get("kind") == "transport" and d.get("src") == "Reaper":
        d = dict(d, **_reaper_data())                     # always fresh data: no delay between Reaper and the browser
        if d.get("pos") is not None and d.get("play"):
            d["pos"] = d["pos"] + min(max(now - d.get("t", now), 0), 1.0)
    elif d.get("kind") == "transport" and d.get("pos") is not None and d.get("play"):
        d["pos"] = d["pos"] + min(max(now - d.get("t", now), 0), 2.0)
    out["d"] = d
    out["fmt"] = kd_get("fmt")
    return out


# ---- Manual QLab main -> backup sync (manual only, locked in SHOW; first a comparison, then you confirm) ----
QS_MAP = os.path.join(os.path.expanduser("~"), "Library", "Application Support", "The Endurance", "qsync-map.json")
QS_COMMON = ["listName", "number", "notes", "colorName", "flagged", "armed", "continueMode", "autoLoad", "preWait", "postWait"]
QS_TYPE = {"audio": ["infiniteLoop", "playCount", "startTime", "endTime", "rate"],
           "video": ["infiniteLoop", "playCount", "startTime", "endTime", "rate"],
           "fade": ["duration", "mode", "stopTargetWhenDone"],
           "group": ["mode", "playlistOptions"],
           "network": ["customString", "parameterValues"]}
QS_LEVEL_TYPES = ("audio", "fade")           # master fader: /cue_id/{id}/level/0/0 (dB)
QS_CREATE = ("group", "fade", "network", "audio", "video", "wait", "memo", "start", "stop", "pause", "load", "reset", "devamp", "goto", "target", "arm", "disarm", "light", "midi", "mtc", "timecode", "script", "text", "camera")
qs = {"busy": False, "diff": None, "ops": [], "log": [], "t": 0.0, "err": ""}
qs_lock = threading.Lock()


class QConn:
    def __init__(self, ip, timeout=3.0):
        self.c = socket.create_connection((ip, QLAB_PORT), timeout=3)
        self.c.settimeout(0.4)
        self.buf = b""
        self.timeout = timeout
        if PASSCODE:
            _sendc(self.c, "/connect", PASSCODE)
        _sendc(self.c, "/updates", 0)

    def close(self):
        try:
            self.c.close()
        except OSError:
            pass

    def ask(self, address, *args, soft=False):
        _sendc(self.c, address, *args)
        end = time.time() + self.timeout
        while time.time() < end:
            try:
                chunk = self.c.recv(65536)
            except socket.timeout:
                continue
            if chunk == b"":
                raise OSError("connection closed")
            frames, self.buf = slip_frames(self.buf + chunk)
            for f in frames:
                try:
                    a, ar = osc_decode(f)
                    r = json.loads(ar[0])
                except Exception:
                    continue
                if a.endswith(address):
                    return r
        if soft:
            return {}
        raise OSError("no reply to " + address)


def _qs_flat(nodes, parent="", out=None):
    out = [] if out is None else out
    for i, n in enumerate(nodes or []):
        if not isinstance(n, dict) or not n.get("uniqueID"):
            continue
        out.append({"id": n["uniqueID"], "type": str(n.get("type", "")).lower(), "parent": parent, "index": i})
        _qs_flat(n.get("cues") or n.get("children") or [], n["uniqueID"], out)
    return out


def qs_read(q):
    r = q.ask("/cueLists")
    data = r.get("data")
    if not isinstance(data, list):
        raise OSError("QLab did not return the cue lists")
    flat = _qs_flat(data)
    for e in flat:
        keys = QS_COMMON + QS_TYPE.get(e["type"], [])
        rr = q.ask("/cue_id/%s/valuesForKeys" % e["id"], json.dumps(keys))
        e["p"] = rr.get("data") if isinstance(rr.get("data"), dict) else {}
        if e["type"] in QS_LEVEL_TYPES:
            try:
                lv = q.ask("/cue_id/%s/level/0/0" % e["id"]).get("data")
                if isinstance(lv, (int, float)):
                    e["p"]["level/0/0"] = lv
            except OSError:
                pass
    return flat


def _qs_mapload():
    try:
        with open(QS_MAP, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def qs_diff(m, b, idmap):
    """Comparison: list of operations to make the backup like the main. Nothing is deleted."""
    bi = {e["id"]: e for e in b}
    ops, extra, matched = [], [], set()
    new_of = {}
    for e in m:
        bid = e["id"] if e["id"] in bi else idmap.get(e["id"])
        if bid not in bi:
            bid = None
        if bid is None:
            if e["type"] not in QS_CREATE:
                ops.append({"op": "skip", "id": e["id"], "txt": "Cue type '%s' not supported: skipped" % e["type"]})
                continue
            ops.append({"op": "create", "id": e["id"], "type": e["type"], "parent": e["parent"], "index": e["index"],
                        "txt": "Create %s cue '%s' (%s)" % (e["type"], e["p"].get("listName", ""), e["p"].get("number", ""))})
            new_of[e["id"]] = None
            for k, v in e["p"].items():
                if v not in (None, "") and k not in ("number",):
                    ops.append({"op": "set", "id": e["id"], "key": k, "val": v, "txt": "  set %s = %s" % (k, v)})
            if e["p"].get("number") not in (None, ""):
                ops.append({"op": "set", "id": e["id"], "key": "number", "val": e["p"]["number"], "txt": "  set number = %s" % e["p"]["number"]})
            continue
        matched.add(bid)
        t = bi[bid]
        for k, v in e["p"].items():
            if k == "duration" and e["type"] not in ("fade",):
                continue
            if t["p"].get(k) != v:
                ops.append({"op": "set", "id": e["id"], "bid": bid, "key": k, "val": v,
                            "txt": "'%s' %s: %s -> %s" % (e["p"].get("listName", ""), k, t["p"].get(k), v)})
        pmain = e["parent"]
        pmapped = (pmain if pmain in bi else idmap.get(pmain, "")) if pmain else ""
        if t["parent"] != pmapped or t["index"] != e["index"]:
            ops.append({"op": "move", "id": e["id"], "bid": bid, "parent": pmain, "index": e["index"],
                        "txt": "Move '%s' to position %d%s" % (e["p"].get("listName", ""), e["index"] + 1, " (inside a group)" if pmain else "")})
    for t in b:
        if t["id"] not in matched:
            extra.append("Only on backup (left untouched): '%s' (%s)" % (t["p"].get("listName", ""), t["type"]))
    return ops, extra


def qs_compare():
    ip, role = other_mac()
    with config_lock:
        r = dict(config["roles"])
    if show_mode():
        return {"ok": False, "err": "SHOW mode: sync is locked"}
    if r.get("self") != "main" or not ip or role != "backup":
        return {"ok": False, "err": "Set this Mac as MAIN and another Mac as BACKUP first (Network interfaces / roles)"}
    if ip_excluded(ip):
        return {"ok": False, "err": "The backup's network port is not monitored"}
    try:
        qm = QConn(QLAB_HOST)
        qb = QConn(ip)
    except OSError as e:
        return {"ok": False, "err": "Cannot connect to QLab: %s" % e}
    try:
        if (qb.ask("/runningCues").get("data") or []):
            return {"ok": False, "err": "The backup has running cues: stop them first"}
        m, b = qs_read(qm), qs_read(qb)
    except OSError as e:
        return {"ok": False, "err": str(e)}
    finally:
        qm.close()
        qb.close()
    ops, extra = qs_diff(m, b, _qs_mapload())
    with qs_lock:
        qs.update(ops=ops, diff={"n": len(ops), "extra": extra, "t": time.time(), "cues_main": len(m), "cues_backup": len(b)}, log=[], t=time.time(), err="")
    return {"ok": True}


def qs_apply():
    if show_mode():
        return {"ok": False, "err": "SHOW mode: sync is locked"}
    with qs_lock:
        ops, d = list(qs["ops"]), qs["diff"]
        if qs["busy"]:
            return {"ok": False, "err": "Sync already running"}
        if not d or time.time() - d["t"] > 600:
            return {"ok": False, "err": "Compare again first (the comparison is older than 10 minutes)"}
        qs["busy"] = True
    ip, role = other_mac()
    log, newmap, failed = [], _qs_mapload(), 0
    try:
        qb = QConn(ip)
        try:
            if (qb.ask("/runningCues").get("data") or []):
                raise OSError("The backup has running cues: stop them first")
            for o in ops:
                if show_mode():
                    log.append("STOPPED: SHOW mode switched on")
                    break
                bid = o.get("bid") or newmap.get(o["id"])
                try:
                    if o["op"] == "create":
                        r = qb.ask("/new", o["type"])
                        nid = r.get("data")
                        if not isinstance(nid, str) or not nid:
                            raise OSError("no id returned")
                        newmap[o["id"]] = nid
                    elif o["op"] == "set" and bid:
                        key = o["key"]
                        r = qb.ask("/cue_id/%s/%s" % (bid, key), o["val"], soft=True)
                        if r.get("status") not in ("ok", None):
                            raise OSError(str(r.get("status")))
                    elif o["op"] == "move" and bid:
                        par = o["parent"]
                        pb = newmap.get(par) or par
                        r = qb.ask("/move/%s" % bid, o["index"], pb, soft=True) if pb else qb.ask("/move/%s" % bid, o["index"], soft=True)
                        if r.get("status") not in ("ok", None):
                            raise OSError(str(r.get("status")))
                    elif o["op"] != "skip":
                        raise OSError("no matching cue on the backup")
                    log.append("OK   " + o["txt"].strip())
                except OSError as e:
                    failed += 1
                    log.append("FAIL " + o["txt"].strip() + " (%s)" % e)
        finally:
            qb.close()
        try:
            os.makedirs(os.path.dirname(QS_MAP), exist_ok=True)
            with open(QS_MAP, "w", encoding="utf-8") as f:
                json.dump(newmap, f)
        except OSError:
            pass
        return {"ok": True, "failed": failed}
    except OSError as e:
        log.append("STOPPED: %s" % e)
        return {"ok": False, "err": str(e)}
    finally:
        with qs_lock:
            qs.update(busy=False, log=log, ops=[], diff=None)


def qs_view():
    with qs_lock:
        d = dict(qs["diff"]) if qs["diff"] else None
        return {"busy": qs["busy"], "diff": d, "ops": [o["txt"] for o in qs["ops"]][:400], "log": list(qs["log"])[-400:], "show": show_mode()}


def _num(v, default=0.0):
    try:
        return float(v)
    except (TypeError, ValueError):
        return default


def cue_timer(uid, c, now):
    """Times of an active cue, computed as in QLab's Active Cues window: duration x percentActionElapsed.
    QLab's percentage follows the real position of the cue (loop, vamp, groups), so the time restarts from zero
    exactly when QLab restarts."""
    e = _num(c.get("actionElapsed"))
    d = _num(c.get("duration"))
    if d <= 0:
        d = _num(c.get("currentDuration"))
    pre, pe_ = _num(c.get("preWait")), _num(c.get("preWaitElapsed"))
    paused = bool(c.get("isPaused"))
    inf = bool(_num(c.get("infiniteLoop")))
    if pre > 0 and pe_ < pre - 0.01 and e <= 0.001:
        return {"elapsed": pe_, "duration": pre, "loop": False, "pre": True, "paused": paused}
    praw = c.get("percentActionElapsed")
    pct = _num(praw, -1.0) if praw is not None else -1.0
    if d > 0 and 0.0 <= pct <= 1.0001:
        return {"elapsed": min(pct, 1.0) * d, "duration": d, "loop": inf, "pre": False, "paused": paused}
    return {"elapsed": e, "duration": d, "loop": inf, "pre": False, "paused": paused}


def get_state():
    with lock:
        out = []
        for uid in order:
            c = cues.get(uid)
            if not c:
                continue
            now_c = time.time()
            t = cue_timer(uid, c, now_c)
            if not t["paused"]:
                # QLab is queried 4 times a second: between one answer and the next the time advances as in QLab
                dt = min(max(now_c - cue_ts.get(uid, now_c), 0.0), 0.4)
                t["elapsed"] = min(t["elapsed"] + dt, t["duration"]) if t["duration"] > 0 else t["elapsed"] + dt
            out.append({
                "id": uid,
                "name": c.get("listName") or "(senza nome)",
                "number": c.get("number", ""),
                "elapsed": t["elapsed"],
                "duration": t["duration"],
                "loop": t["loop"],
                "pre": t["pre"],
                "paused": t["paused"],
            })
        wname = ws_names.get(ws_id) or (next(iter(ws_names.values())) if len(ws_names) == 1 else "")
        hws = [{"name": n or "(senza nome)", "current": i == ws_id or len(ws_names) == 1}
               for i, n in ws_names.items()]
    now_ = time.time()
    with pull_lock:
        pull_out = {ip: dict(pulled.get(ip) or {"ok": None}, on=True) for ip in pull_set}
        for k in [k for k, t in watchers.items() if now_ - t > 30]:
            del watchers[k]
        watch_out = [k for k, t in watchers.items() if now_ - t <= 10]
    with peers_lock:
        plist = sorted((dict(p) for p in peers.values()), key=lambda p: ipaddress.ip_address(p["ip"]))
    with config_lock:
        roles = dict(config["roles"])
    for p in plist:
        p.pop("seen", None)
        p["role"] = roles.get(p["ip"], "")
    bkv, bcues = bk_view()
    with calls_lock:
        callsl = [dict(c) for c in calls if now_ - c["t"] < 3600]
    return {"online": time.time() - last_reply < 3, "cues": out, "sys": dict(stats), "version": VERSION,
            "net": list(net), "port": HTTP_PORT, "workspace": wname, "netsel": netsel_summary(),
            "self": dict(selfinfo), "osc_enabled": osc_ctl["enabled"], "autosave": dict(autosave), "now": time.time(), "defcon": dict(defcon), "pull": pull_out, "watchers": watch_out, "workspaces": hws, "peers": plist, "host_name": host_name(),
            "roles": roles, "mode": config.get("mode", "edit"), "key_app": config.get("key_app", ""), "advice": advice_calc(), "pings": dict(pings),
            "intervals": {"sys": SYS_INTERVAL, "apps": APPS_SECONDS, "qlab": POLL_SECONDS, "peers": PEERS_SECONDS},
            "bk": bkv, "bcues": bcues, "calls": callsl, "kd": kd_view(), "key_label": key_canon(config.get("key_app", "")) or "", "key_name": LPQ if config.get("lp_extra") else "", "lpx": lpx_view(), "key_pats": key_pats(config.get("key_app", "")) + (key_pats("Live Professor") if config.get("lp_extra") else []), "key_beta": (key_canon(config.get("key_app", "")) or "QLab") not in KEY_STABLE}


PAGE = """<!doctype html>
<html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-title" content="The Endurance">
<title>The Endurance</title>
<style>
  :root{--or:#ff8a00;--dim:#7a4300}
  html{-webkit-text-size-adjust:100%}
  html,body{margin:0;background:#000;color:var(--or);font-family:"Endurance Sans","DejaVu Sans Condensed","Helvetica Neue",Arial,sans-serif}
  body{padding:env(safe-area-inset-top) 12px calc(env(safe-area-inset-bottom) + 24px);max-width:520px;margin:0 auto}
  /*FONT*/
  .serif{font-family:"Endurance Serif","Hiragino Mincho ProN","Yu Mincho",Georgia,"Times New Roman",serif;font-weight:900}
  /* intestazione */
  .head{display:flex;align-items:center;justify-content:center;gap:14px;padding:12px 0 8px}
  .brand{display:flex;align-items:center;gap:9px}
  .brand svg{width:40px;height:40px;flex:none}
  .title{font-size:17px;line-height:1;letter-spacing:.06em;text-transform:uppercase;transform:scaleX(.86);transform-origin:center;margin:0 -10px}
  .ver{font-size:11px;letter-spacing:.14em;color:var(--dim)}
  .tags{display:flex;flex-wrap:wrap;justify-content:center;gap:4px;margin:2px 0 10px}
  .kj{color:var(--or);text-decoration:none;border-color:#39ff88 !important;color:#39ff88}
  .tag{border:1px solid var(--or);padding:1px 5px;font-size:10px;letter-spacing:.06em;text-transform:uppercase;white-space:nowrap;max-width:100%;overflow:hidden;text-overflow:ellipsis;box-sizing:border-box}
  /* pannelli esagonali */
  .hx{--k:14px;position:relative;padding:2px;background:var(--c,#ff8a00);
      clip-path:polygon(var(--k) 0,calc(100% - var(--k)) 0,100% var(--k),100% calc(100% - var(--k)),calc(100% - var(--k)) 100%,var(--k) 100%,0 calc(100% - var(--k)),0 var(--k))}
  .hx>.in{background:#000;padding:10px 14px;
      clip-path:polygon(calc(var(--k) - 1px) 0,calc(100% - var(--k) + 1px) 0,100% calc(var(--k) - 1px),100% calc(100% - var(--k) + 1px),calc(100% - var(--k) + 1px) 100%,calc(var(--k) - 1px) 100%,0 calc(100% - var(--k) + 1px),0 calc(var(--k) - 1px))}
  .nodes{display:flex;justify-content:center;gap:10px}
  .nd{position:relative;width:80px;height:64px;flex:none}
  .nd svg{position:absolute;left:0;top:0;width:80px;height:64px;display:block}
  .nd polygon{fill:none;stroke:var(--c);stroke-width:2;stroke-linejoin:round}
  .nt{position:absolute;left:0;top:0;width:80px;height:64px;box-sizing:border-box;padding:0;display:flex;flex-direction:column;align-items:center;justify-content:center;text-align:center}
  .nc{font-size:8px;letter-spacing:.04em;color:var(--dim);line-height:9px;white-space:nowrap}
  .nsub{position:absolute;left:0;top:48px;text-indent:.04em;font-size:4.5px;letter-spacing:.04em;text-align:center;width:100%;color:var(--dim);line-height:7px;white-space:nowrap;text-transform:uppercase}
  .nv{font-size:20px;font-weight:700;line-height:22px;font-variant-numeric:tabular-nums}
  .ns{text-indent:.08em;font-size:8px;letter-spacing:.08em;color:var(--c);line-height:9px;white-space:nowrap}
  .nj{font-size:8px;color:var(--c);opacity:.7;line-height:10px;white-space:nowrap}
  @media (max-width:330px){.nodes{gap:4px}}
  .bl{animation:bl 1s steps(2,start) infinite}
  .tag.dc1{background:#ff2d2d;color:#000 !important;font-weight:700}
  a.tag{text-decoration:none;cursor:pointer}
  #alert.bk b{animation:thr 1s steps(2,start) infinite}
  .tag.dcb{animation:thr 1s steps(2,start) infinite}
  @keyframes thr{50%{opacity:.12}}
  @keyframes abk{50%{opacity:0}}
  .advb{margin:2px 0 8px;border:1px solid var(--c);color:var(--c);padding:5px 8px;font-size:9px;letter-spacing:.04em;line-height:1.5;text-align:left}
  .advb b{display:block;letter-spacing:.14em;font-size:10px;margin-bottom:2px}
  .advb span{color:#e8a14a}
  .advb.s1{--c:#ffd60a}.advb.s2{--c:#ff8a00}.advb.s3{--c:#ff2d2d}
  .nm{font-size:7px;letter-spacing:.08em;color:var(--dim);text-transform:uppercase;padding:0 0 2px;border-bottom:1px solid rgba(255,138,0,.22)}
  #alert{text-align:center;display:none;margin:2px 0 8px}
  #alert b{display:inline-block;background:#000;border:2px solid #ff2d2d;color:#ff2d2d;padding:6px 12px;font-size:18px;letter-spacing:.14em;max-width:100%;box-sizing:border-box}
  #alert i{display:block;font-style:normal;font-size:9px;letter-spacing:.1em;margin-top:6px;color:#ff2d2d;background:#000;padding:2px 6px;display:inline-block}
  #lost.bk{animation:abk .4s steps(2,start) infinite}
  #lost{background:#ff2d2d;color:#000;text-align:center;font-weight:700;letter-spacing:.12em;font-size:12px;padding:6px 8px;margin:2px 0 8px;display:none}
  #mute{position:fixed;right:10px;bottom:calc(env(safe-area-inset-bottom) + 10px);z-index:10;display:none;background:#000;color:#ff8a00;border:1px solid #ff8a00;font:inherit;font-size:10px;letter-spacing:.08em;padding:6px 9px;text-transform:uppercase}
  .defwhy{text-align:center;font-size:8px;letter-spacing:.08em;text-transform:uppercase;margin:-2px 0 8px;min-height:0}
  @keyframes bl{50%{opacity:.35}}
  /* sezioni */
  .sec{display:flex;align-items:center;gap:8px;margin:16px 0 6px;font-size:11px;letter-spacing:.2em;text-transform:uppercase}
  .sec i{flex:1;height:1px;background:var(--or);opacity:.45}
  .sec .jp{color:var(--dim);letter-spacing:.1em}
  .s8{font-size:8px}.s9{font-size:9px}.tight{margin:8px 0 3px}
  /* app */
  .ar{display:flex;align-items:center;gap:8px;padding:2px 0;border-bottom:1px solid rgba(255,138,0,.22)}
  .ar i{width:3px;height:10px;background:var(--c)}
  .an{flex:1;min-width:0;color:var(--c);font-size:9px;font-weight:700;letter-spacing:.04em;text-transform:uppercase;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
  .as{font-size:8px;color:var(--or);white-space:nowrap;font-variant-numeric:tabular-nums}
  .as b{color:var(--dim);font-weight:400}
  /* cue */
  .cue{margin:8px 0}
  .cn{font-size:8px;letter-spacing:.06em;text-transform:uppercase;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
  .ct{font-size:43px;font-weight:700;line-height:1.1;font-variant-numeric:tabular-nums}
  .cs{font-size:8px;color:var(--dim);letter-spacing:.08em;margin-bottom:6px}
  .seg{height:8px;background:repeating-linear-gradient(90deg,#3a1f00 0 6px,#000 6px 9px)}
  .seg div{height:100%;background:repeating-linear-gradient(90deg,var(--c) 0 6px,#000 6px 9px)}
  .empty{color:var(--dim);font-size:12px;letter-spacing:.12em;padding:8px 0}
  .pull{font-size:8px;letter-spacing:.06em;text-transform:uppercase;margin:2px 0 6px;display:flex;gap:8px;align-items:center;flex-wrap:wrap}
  .pull .tag{font-size:8px;padding:0 4px}
  .nr{display:flex;flex-wrap:wrap;align-items:baseline;gap:0 8px;padding:1px 0;border-bottom:1px solid rgba(255,138,0,.22);font-size:8px}
  .nn{width:132px;flex:none;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;color:var(--dim);letter-spacing:.1em;text-transform:uppercase;font-size:8px}
  .nu{flex:none;width:104px;color:var(--or);letter-spacing:0;font-variant-numeric:tabular-nums;white-space:nowrap}
  .nq{flex:1;min-width:0;text-align:right;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;letter-spacing:.04em;text-transform:uppercase}
  .cores{display:flex;gap:3px;height:26px;margin:2px 0 6px}
  .cgh{display:flex;justify-content:space-between;align-items:baseline;font-size:8px;letter-spacing:.12em;text-transform:uppercase;color:var(--dim);margin-top:8px}
  .cgh b{font-weight:400;font-size:9px}
  .cores i{flex:1;min-width:0;background:#160b00;border-bottom:2px solid #5a3000;display:flex;align-items:flex-end}
  .cores b{display:block;width:100%}
  .credit{margin:22px 0 4px;font-size:5.5px;letter-spacing:.1em;text-transform:uppercase;color:var(--dim)}
  .stop{display:none;position:fixed;right:12px;bottom:calc(env(safe-area-inset-bottom) + 6px);z-index:5;font-family:inherit;font-size:11px;letter-spacing:.14em;text-transform:uppercase;color:#ff2d2d;background:#000;border:1px solid #ff2d2d;padding:3px 10px;cursor:pointer;-webkit-appearance:none;border-radius:0}
  .app .stop{display:block}
  .err{color:#ff2d2d;font-size:11px;letter-spacing:.06em;padding:6px 0;text-transform:uppercase}
  .cols{display:grid;grid-template-columns:2fr 1fr;gap:8px;align-items:start}
  .cols>div{min-width:0}
  .kh{font-size:7px;letter-spacing:.12em;text-transform:uppercase;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;border-bottom:1px solid currentColor;padding-bottom:2px;margin-bottom:2px}
  .cue.sm{--k:8px;margin:5px 0}
  .cue.sm>.in{padding:5px 7px}
  .cue.sm .ct{font-size:22px}
  .cue.sm .cn,.cue.sm .cs{font-size:6.5px}
  .empty.s{font-size:9px}
  .lpl{font-size:9px;letter-spacing:.08em;margin:0 0 3px}
  .smrow{display:flex;gap:8px;flex-wrap:wrap}
  .smcol{flex:1 1 100px;min-width:0}
  .smcol .cn{white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
  .smrow .mt b{font-size:13px}
  .smrow .mt span{font-size:7px}
  .mgrid{display:grid;grid-template-columns:repeat(2,1fr);gap:5px;margin-top:4px}
  .mt{border:1px solid #2ee6c8;padding:3px 7px;display:flex;justify-content:space-between;align-items:baseline}
  .mt b{font-size:15px;color:#2ee6c8;font-variant-numeric:tabular-nums}
  .mt span{font-size:7px;letter-spacing:.08em;color:#7a4300;text-transform:uppercase}
  #callv{display:none;position:fixed;left:0;top:0;right:0;bottom:0;z-index:60;background:rgba(0,0,0,.82);align-items:center;justify-content:center}
  .chx{width:min(92vw,440px);aspect-ratio:1.15;background:#39ff88;clip-path:polygon(25% 0,75% 0,100% 50%,75% 100%,25% 100%,0 50%);display:flex;align-items:center;justify-content:center}
  .chi{width:calc(100% - 6px);height:calc(100% - 6px);background:#031a0c;clip-path:polygon(25% 0,75% 0,100% 50%,75% 100%,25% 100%,0 50%);display:flex;flex-direction:column;align-items:center;justify-content:center;text-align:center;color:#39ff88;padding:0 18%;box-sizing:border-box}
  .cl1{font-size:11px;letter-spacing:.3em}
  .cl2{font-size:24px;font-weight:700;letter-spacing:.04em;margin:4px 0;font-variant-numeric:tabular-nums}
  .cl3{font-size:13px;letter-spacing:.1em;text-transform:uppercase;max-width:100%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
  .cl4{font-size:9px;letter-spacing:.14em;margin-top:6px;color:#b6e63a}
  .chi button{margin-top:12px;font:inherit;font-size:11px;letter-spacing:.14em;color:#000;background:#39ff88;border:0;padding:7px 12px;cursor:pointer}
</style></head><body>
<button id="mute">Mute blink 60s</button>
<div id="wrap">
<div class="head"><div class="brand">
<svg viewBox="0 0 40 40" fill="none" stroke="#ff8a00" stroke-width="1.5" stroke-linejoin="round"><circle cx="20" cy="20" r="18" stroke-width="1.3"/><g transform="translate(19.6 20.6) scale(0.032) translate(-600 -532)" stroke-linejoin="round" stroke-linecap="round" fill="none"><path d="M640 130 C705 130 760 150 790 178 L928 215 L800 258 L765 298 L730 322 C790 345 832 450 832 620 L830 800 L782 932 L470 932 L276 750 C275 600 330 420 440 330 C470 290 475 235 520 185 C560 148 600 130 640 130 Z" fill="#000" stroke="#000" stroke-width="75"/><path d="M640 130 C705 130 760 150 790 178 L928 215 L800 258 L765 298 L730 322 C790 345 832 450 832 620 L830 800 L782 932 L470 932 L276 750 C275 600 330 420 440 330 C470 290 475 235 520 185 C560 148 600 130 640 130 Z" stroke="#ff8a00" stroke-width="42.1875" fill="#000"/><path d="M725 328 C610 335 565 440 556 530 C552 620 570 650 566 700 L512 826 L428 862 L455 716 L405 590 C440 480 500 400 560 350 C610 316 670 318 725 328 Z" stroke="#ff8a00" stroke-width="42.1875"/><path d="M790 178 L742 218 L800 258 M742 226 L920 214" stroke="#ff8a00" stroke-width="42.1875"/></g></svg>
<div class="title serif">The Endurance</div></div><div class="ver" id="ver"></div></div>
<div id="lost">HOST LOST</div>
<div class="tags" id="tags"></div>
<div class="tags" id="tabs" style="margin:0 0 6px"></div>
<div class="defwhy" id="defwhy"></div>
<div id="alert"><b>IMMINENT THREAT</b><br><i id="alwhy"></i></div>
<div id="adv"></div>
<div class="nodes" id="nodes"></div>
<div class="defwhy" id="modeln" style="margin:4px 0 0;color:var(--dim)"></div>
<div class="tags" id="memtags" style="margin:8px 0 0;justify-content:center;flex-wrap:nowrap;gap:3px"></div>
<div id="cores"></div>
<div class="sec s8 tight"><a class="tag" href="/network" target="_blank" style="color:#ff8a00">Network &rsaquo;</a><i></i></div>
<div id="net"></div>
<div id="keyrow"></div>
<div class="sec s9" id="apHd" style="cursor:pointer"><span>Applications</span><i></i><b id="apArr" style="font-size:14px;line-height:1;padding:0 4px">&#9656;</b></div>
<div id="apps" style="display:none"></div>
<div class="sec s8"><span id="kdt">Key app in details</span><i></i></div>
<div id="list"></div>
<div class="credit serif">crafted by Francesco Lo Brano</div>
<button class="stop" id="stop">Stop</button>
<div id="callv"></div>
</div>
<script>
function fmt(s){s=Math.max(0,s);var m=Math.floor(s/60),x=Math.floor(s%60);
  return (m<10?"0":"")+m+":"+(x<10?"0":"")+x}
function pad(n){return (n<10?"0":"")+n}
function esc(t){return String(t).replace(/[&<>]/g,function(c){return {"&":"&amp;","<":"&lt;",">":"&gt;"}[c]})}
// soglie: <50 verde, 50-80 giallo, 80-90 arancione, >90 rosso
function lvl(v){return v<50?"#39ff88":v<80?"#ffd60a":v<90?"#ff8a00":"#ff2d2d"}
// colori per app (cerca il testo nel nome, senza spazi e minuscolo)
var G="#c8c8c8", B="#64d2ff", W="#ffffff";
var APPCOL=[["qlab","#bf5af2"],["liveprofessor","#ffd60a"],["theendurance","#39ff88"],
            ["workbench",W],["wsm",W],["soundbase",W],["smaart",W],
            ["compass",B],["r1",B],["arraycalc",B],["mapp3d",B],["finder",B],
            ["firefox",G],["opera",G],["chrome",G],["safari",G],["brave",G],["edge",G],["vivaldi",G],["arc",G],["chromium",G],["orion",G],["duckduckgo",G]];
function appcol(n){var k=String(n).toLowerCase().replace(/[^a-z0-9]/g,"");
  for(var i=0;i<APPCOL.length;i++){var p=APPCOL[i][0];
    if(p.length<=3?k===p:k.indexOf(p)>=0)return APPCOL[i][1]}
  return "#ffb04d"}
// swap: sotto 1 GB verde, 1-3 GB arancione (il Mac si sta sforzando), oltre 3 GB rosso
function swapcol(g){return g<1?"#39ff88":g<3?"#ff8a00":"#ff2d2d"}
// font size that keeps the text inside the hexagon: never wider than k/len of a character (monospace ~0.6em)
function nfit(t,max,k){var n=String(t).replace(/&[a-z]+;/g,"x").length||1;return Math.max(6,Math.min(max,Math.floor(k/n)))}
function node(val,lab,c,blink,sub){
  return '<div class="nd'+(blink?' bl':'')+'" style="--c:'+c+'">'
    +'<svg viewBox="0 0 80 64" aria-hidden="true"><polygon points="20,1 60,1 79,32 60,63 20,63 1,32"/></svg>'
    +'<div class="nt"><div class="nv" style="color:'+c+';font-size:'+nfit(val,sub?15:20,76)+'px">'+val+'</div>'
    +'<div class="ns" style="font-size:'+nfit(lab,8,60)+'px">'+lab+'</div>'+(sub?'<div class="nsub">'+sub+'</div>':'')+'</div></div>';
}
function tag(t,c){return '<span class="tag"'+(c?' style="color:'+c+';border-color:'+c+'"':'')+'>'+t+'</span>'}

function coreHtml(y){
  var c=y.cores||[],t=y.core_types;
  function strip(idx){return '<div class="cores">'+idx.map(function(i){var v=c[i];
    return '<i title="CORE '+(i+1)+(t?' ('+t[i]+')':'')+': '+Math.round(v)+'%"><b style="height:'+Math.min(100,v)+'%;background:'+lvl(v)+'"></b></i>'}).join("")+'</div>'}
  if(!t||t.length!==c.length)return strip(c.map(function(_,i){return i}));
  var h="";
  [["P","Performance"],["E","Efficiency"]].forEach(function(x){
    var idx=[];t.forEach(function(k,i){if(k===x[0])idx.push(i)});
    if(!idx.length)return;
    var avg=idx.reduce(function(a,i){return a+c[i]},0)/idx.length;
    h+='<div class="cgh"><span>'+x[1]+' cores &middot; '+idx.length+'</span><b style="color:'+lvl(avg)+'">'+Math.round(avg)+'%</b></div>'+strip(idx)});
  return h;
}
// DEFCON: il livello e' calcolato dal Endurance sul Mac (s.defcon), cosi' resta nello storico anche a pagina chiusa.
var DEFCOL={5:"#39ff88",4:"#b6e63a",3:"#ffd60a",2:"#ff8a00",1:"#ff2d2d"};
function defView(s){
  var d=s.defcon;
  if(!d||!s.sys||(s.sys.cpu==null&&s.sys.ram==null))return {tag:'<a class="tag" href="/defcon" target="_blank" style="color:#7a4300;border-color:#7a4300">DEFCON -- &rsaquo;</a>',why:"",lv:5,blink:0};
  var lv=d.level,c=DEFCOL[lv];
  return {lv:lv,blink:d.blink||0,
    tag:'<a class="tag dcl'+(lv===1?' dc1':'')+'" href="/defcon" target="_blank" style="color:'+(lv===1?'#000':c)+';border-color:'+c+'" title="DEFCON 5 = no risk, 1 = crash or glitch imminent. Tap for the log">DEFCON '+lv+' &rsaquo;</a>',
    why:lv<5&&d.why&&d.why.length?'<span style="color:'+c+'">'+d.why.map(esc).join(" &middot; ")+'</span>':""};
}
function fitRow(id){var e=document.getElementById(id),f=10;e.style.fontSize="";e.style.flexWrap="nowrap";
  var ts=e.querySelectorAll(".tag");
  function set(f){for(var i=0;i<ts.length;i++){ts[i].style.fontSize=f+"px";ts[i].style.overflow="visible";ts[i].style.maxWidth="none";ts[i].style.flex="none";ts[i].style.padding="1px "+(f>8?4:3)+"px"}}
  set(f);while(f>6.5&&e.scrollWidth>e.clientWidth+1){f-=.5;set(f)}if(e.scrollWidth>e.clientWidth+1){e.style.flexWrap="wrap";e.style.justifyContent="center";set(8)}}
function pullB(e){pullT(e.getAttribute("data-ip"),e.getAttribute("data-on"))}
function pullT(ip,on){fetch("/pull?ip="+encodeURIComponent(ip)+"&on="+on,{method:"POST"}).catch(function(){})}
function setH(id,h){var e=document.getElementById(id);if(e._h!==h){e._h=h;e.innerHTML=h}}
// stato: mute 60 s, HOST LOST, keep-awake
var lastRaw1=0,lostAt=0,lastOk=Date.now(),curBlink=0,curLv=5,curWhy="",muteUntil=0;
try{muteUntil=+localStorage.getItem("enduranceMute")||0}catch(e){}
function applyBlink(){
  var m=Date.now()<muteUntil, b=m?0:curBlink, al=document.getElementById("alert"), dl=document.querySelector("#tabs a.dcl");
  if(dl)dl.className=dl.className.replace(/ ?dcb/g,"")+(b>0?" dcb":"");
  al.style.display=Date.now()-lastRaw1<10000?"block":"none";al.className=b===1?"bk":"";
  document.getElementById("alwhy").textContent=curWhy;
  var mb=document.getElementById("mute");
  mb.style.display=curBlink>0?"block":"none";
  mb.textContent=m?"Muted "+Math.ceil((muteUntil-Date.now())/1000)+"s":"Mute blink 60s";
  var lo=document.getElementById("lost"),isl=Date.now()-lastOk>5000;
  if(isl&&!lostAt)lostAt=Date.now();if(!isl)lostAt=0;
  lo.style.display=isl?"block":"none";lo.className=isl&&Date.now()-lostAt<2000?"bk":"";
}
document.getElementById("mute").onclick=function(){muteUntil=Date.now()+60000;try{localStorage.setItem("enduranceMute",muteUntil)}catch(e){}applyBlink()};
setInterval(applyBlink,500);
// ---- key app in details ----
var GREEN="#39ff88", BLUE="#64d2ff", RED="#ff2d2d", AQUA="#2ee6c8", ORG="#ff8a00";
// key app colours: aqua = fine, orange = under 30 s, red = under 10 s
function tcol(rem,base){return rem<10?RED:rem<30?ORG:base}
function cueHtml(c,base,small){
  var d=c.duration, rem=d-c.elapsed, pct=d>0?Math.min(100,c.elapsed/d*100):0;
  var low=d>0&&rem<10&&!c.pre, col=(d>0&&!c.pre)?tcol(rem,base):base;
  return '<div class="hx cue'+(low?' bl':'')+(small?' sm':'')+'" style="--c:'+col+'"><div class="in">'
   +'<div class="cn">'+esc(c.number)+' // '+esc(c.name)+'</div>'
   +'<div class="ct" style="color:'+col+'">'+(d>0?'-'+fmt(rem):fmt(c.elapsed))+'</div>'
   +'<div class="cs">'+(c.pre?'PRE-WAIT &middot; ':c.loop?'LOOP &middot; ':c.paused?'PAUSED &middot; ':'')+fmt(c.elapsed)+' / '+(d>0?fmt(d):(c.loop?'&infin;':'---'))+'</div>'
   +(d>0?'<div class="seg"><div style="width:'+pct+'%"></div></div>':'')+'</div></div>';
}
function colHead(txt,col){return '<div class="kh" style="color:'+col+'">'+txt+'</div>'}
function posTxt(d,fmtm){
  if(fmtm==="bars"&&d.bars&&d.bars.length>=2)return 'BAR '+d.bars[0]+' &middot; BEAT '+d.bars[1];
  return d.pos==null?'---':fmt(d.pos);
}
function detailsHtml(s){
  var kd=s.kd||{}, lab=s.key_label||s.key_app||"", d=kd.d, y=s.sys||{}, ky=y.key;
  if(lab==="QLab"||!lab){
    var mine=(s.roles||{}).self, bk=s.bk, lc=GREEN;
    var lh='', rh='';
    var lx=s.lpx, lpl='';
    if(lx){var lv=lx.pct, lcol=lv===undefined?"#7a4300":lv>=90?RED:lv>=70?ORG:AQUA;
      lpl='<div class="lpl" style="color:'+lcol+'">LIVEPROFESSOR DSP LOAD: '+(lv===undefined?'--':lv.toFixed(0)+'%')+'</div>'}
    var mc=(s.cues||[]).map(function(c){return cueHtml(c,bk?(mine==="backup"?BLUE:GREEN):AQUA,!!bk)}).join("")||'<div class="empty">NO ACTIVE CUE</div>';
    if(!bk)return lpl+mc;
    var rc=bk.role==="backup"?BLUE:GREEN;
    var rcues=(s.bcues||[]).map(function(c){return cueHtml(c,rc,true)}).join("");
    var rhead=bk.online?colHead(esc(bk.role.toUpperCase())+' &middot; '+esc(bk.host||bk.ip),rc):colHead(esc(bk.role.toUpperCase())+' UNREACHABLE',RED);
    return lpl+'<div class="cols"><div>'+colHead(esc((mine||"this mac").toUpperCase())+' &middot; '+esc(s.host_name||""),mine==="backup"?BLUE:GREEN)+mc+'</div>'
      +'<div>'+rhead+(bk.online?(rcues||'<div class="empty s">NO CUE</div>'):'')+'</div></div>';
  }
  var remote=lab==="vMix"||lab==="PowerPoint"||lab==="Arena";
  if((!ky||!ky.running)&&!(remote&&d))return '<div class="empty">'+esc(lab.toUpperCase())+' NOT RUNNING'+(remote?'<br><span style="font-size:9px">waiting for its data</span>':'')+'</div>';
  if(kd.err)return '<div class="err">'+esc(kd.err)+'</div>';
  if(!d||d.kind==="none")return '<div class="empty">'+(d&&d.note?esc(d.note):'NO DETAILS READER FOR '+esc(lab.toUpperCase())+' YET')+'<br><span style="font-size:9px">running, CPU and RAM are monitored</span></div>';
  if(d.kind==="keynote"){
    if(!d.doc)return '<div class="empty">NO PRESENTATION OPEN</div>';
    return '<div class="hx cue" style="--c:'+AQUA+'"><div class="in"><div class="cn">'+esc(d.doc)+'</div><div class="ct" style="color:'+AQUA+'">'+d.slide+' / '+d.total+'</div>'
      +'<div class="cs">SLIDE &middot; '+Math.max(0,d.total-d.slide)+' REMAINING</div></div></div>';
  }
  if(d.kind==="cues"){
    var hh=d.ws?'<div class="cs" style="margin:2px 0 0">'+esc(d.ws)+'</div>':"";
    return hh+(d.cues.length?d.cues.map(function(c){return cueHtml(c,AQUA,false)}).join(""):'<div class="empty">NO ACTIVE CUE</div>');
  }
  if(d.kind==="ppt"){
    var h2='';
    if(d.err)h2+='<div class="err">'+esc(d.err)+'</div>';
    if(d.doc)h2+='<div class="hx cue" style="--c:'+AQUA+'"><div class="in"><div class="cn">'+esc(d.doc)+'</div><div class="ct" style="color:'+AQUA+'">'+(d.slide||"-")+' / '+(d.total||"-")+'</div>'
      +'<div class="cs">SLIDE &middot; '+(d.total&&d.slide?Math.max(0,d.total-d.slide):"-")+' REMAINING</div></div></div>';
    else if(!d.err)h2+='<div class="empty">NO PRESENTATION OPEN</div>';
    if(d.rem!=null||d.pos!=null){
      var col=d.rem!=null?tcol(d.rem,AQUA):AQUA, low=d.rem!=null&&d.rem<10;
      h2+='<div class="hx cue'+(low?' bl':'')+'" style="--c:'+col+'"><div class="in"><div class="cn">VIDEO &middot; '+esc(String(d.state||"").toUpperCase())+'</div>'
        +'<div class="ct" style="color:'+col+'">'+(d.rem!=null?'-'+fmt(d.rem):fmt(d.pos||0))+'</div>'
        +'<div class="cs">'+(d.pos!=null?fmt(d.pos):'---')+' / '+(d.dur!=null?fmt(d.dur):'---')+'</div></div></div>';
    }else h2+='<div class="cs" style="margin-top:4px">VIDEO TIME: OSCPOINT ADD-IN NOT SENDING (UDP '+d.port+')</div>';
    return h2;
  }
  if(d.kind==="smaart"){
    var chs=d.chs||[];
    if(d.err&&!d.fresh)return '<div class="err">'+esc(d.err)+'</div>';
    if(!d.fresh)return '<div class="empty">WAITING FOR SMAART<br><span style="font-size:9px">Options &gt; Preferences &gt; API &gt; Enabled, and start logging</span></div>';
    var one=chs.length===1;
    return '<div class="smrow">'+chs.map(function(c){
      if(!c.fresh||!c.order.length)return '<div class="smcol"><div class="empty">'+esc(c.name)+'<br><span style="font-size:9px">WAITING FOR DATA</span></div></div>';
      var mm=c.metrics, ord=c.order, mc=c.viol?RED:AQUA;
      var tiles=ord.slice(1,one?5:3).map(function(k){return '<div class="mt"><b>'+mm[k].toFixed(1)+'</b><span>'+esc(k)+'</span></div>'}).join("");
      return '<div class="smcol"><div class="hx cue'+(one?'':' sm')+'" style="--c:'+mc+'"><div class="in"><div class="cn">'+esc(c.name)+'</div>'
        +'<div class="ct" style="color:'+mc+'">'+mm[ord[0]].toFixed(1)+' <span style="font-size:'+(one?14:10)+'px">dB</span></div><div class="cs">'+esc(ord[0].toUpperCase())+'</div></div></div>'
        +(tiles?'<div class="mgrid"'+(one?'':' style="grid-template-columns:1fr"')+'>'+tiles+'</div>':'')+'</div>';
    }).join("")+'</div>';
  }
  if(d.kind==="dsp"){
    if(d.pct===undefined)return '<div class="empty">WAITING FOR LIVEPROFESSOR<br><span style="font-size:9px">Options &gt; Project Options &gt; Osc Control: enable, input port '+d.inp+', output port '+d.out+', OSC Controller Address = the IP of this Mac (127.0.0.1 if LiveProfessor is on this Mac)</span></div>';
    var dc=d.pct>=90?RED:d.pct>=70?ORG:AQUA;
    return '<div class="hx cue" style="--c:'+dc+'"><div class="in"><div class="cn">LIVEPROFESSOR &middot; DSP LOAD</div>'
      +'<div class="ct" style="color:'+dc+'">'+d.pct.toFixed(0)+'<span style="font-size:14px"> %</span></div><div class="cs">OSC &middot; /DSPmeter</div></div></div>';
  }
  if(d.kind==="transport"){
    if(d.rec===undefined)return '<div class="empty">WAITING FOR '+esc(d.src.toUpperCase())+(d.port?' ON UDP PORT '+d.port:'')+'<br><span style="font-size:9px">press play or record in '+esc(d.src)+'; check its OSC device IP and port</span></div>';
    var rc2=d.rec?RED:AQUA;
    return '<div class="hx cue'+(d.rec?' bl':'')+'" style="--c:'+rc2+'"><div class="in"><div class="cn">'+esc(d.src.toUpperCase())+' &middot; '+(d.play?'PLAYING':'STOPPED')+'</div>'
      +'<div class="ct" style="color:'+rc2+';font-size:30px">'+(d.rec?'&#9679; RECORDING':'NOT RECORDING')+'</div>'
      +'<div class="cs" style="font-size:11px">'+posTxt(d,kd.fmt)+'</div></div></div>';
  }
  return "";
}
// ---- call ----
var dismissed={};
function callB(e){var ip=e.getAttribute("data-ip");e.style.opacity=.4;fetch("/call?ip="+encodeURIComponent(ip),{method:"POST"}).then(function(r){return r.text()}).then(function(t){e.style.opacity=1;e.textContent=t==="ok"?"CALLED":"RETRY";setTimeout(function(){e.textContent="CALL"},1800)}).catch(function(){e.style.opacity=1})}
function dismissCall(id){dismissed[id]=1;document.getElementById("callv").style.display="none";fetch("/calldismiss?id="+id,{method:"POST"}).catch(function(){})}
function callHtml(s){
  var v=document.getElementById("callv");
  if(!v)return;
  if(location.search.indexOf("app=1")>=0){v.style.display="none";return}
  var cs=(s.calls||[]).filter(function(c){return !dismissed[c.id]});
  if(!cs.length){if(v._k!==""){v._k="";v.style.display="none"}return}
  var c=cs[cs.length-1], k=c.id+"/"+cs.length;
  if(v._k===k){v.style.display="flex";return}
  v._k=k;
  v.innerHTML='<div class="chx"><div class="chi"><div class="cl1">CALL FROM</div><div class="cl2">'+esc(c.ip)+'</div><div class="cl3">'+esc(c.name)+(c.role?' &middot; '+esc(c.role.toUpperCase()):'')+'</div>'
    +(cs.length>1?'<div class="cl4">+'+(cs.length-1)+' MORE CALL'+(cs.length>2?'S':'')+'</div>':'')
    +'<button onclick="dismissCall('+c.id+')">DISMISS CALL</button></div></div>';
  v.style.display="flex";
}
var apOpen=false;try{apOpen=localStorage.getItem("endApps")==="1"}catch(e){}
function apApply(){document.getElementById("apps").style.display=apOpen?"block":"none";document.getElementById("apArr").innerHTML=apOpen?"&#9662;":"&#9656;"}
document.getElementById("apHd").onclick=function(){apOpen=!apOpen;try{localStorage.setItem("endApps",apOpen?"1":"0")}catch(e){}apApply()};apApply();
var lastTags=null;
var tbusy=0;
function tick(){
  if(document.hidden||Date.now()-tbusy<4000&&tbusy)return;tbusy=Date.now();
  fetch("/state",{cache:"no-store"}).then(function(r){return r.json()}).then(function(s){
    tbusy=0;lastOk=Date.now();
    var y=s.sys||{}, on=s.online;
    document.getElementById("ver").textContent="VER "+(s.version||"");
    var ws=s.workspaces||[], pe=s.peers||[], PC="#64d2ff", tg="";
    if(!on)tg+=tag("HOST:OFFLINE","#ff2d2d");
    else if(!ws.length)tg+=tag("HOST:ONLINE","#39ff88");
    else ws.forEach(function(w){tg+=tag("HOST WORKSPACE: "+esc(w.name),w.current?"#39ff88":"#1f9a52")});
    var dv=defView(s);curBlink=dv.blink;curLv=dv.lv;if(s.defcon&&s.defcon.raw===1)lastRaw1=Date.now();curWhy=dv.why?(s.defcon.why||[]).join(" / "):"";applyBlink();
    var ns=s.netsel||{configured:true};
    setH("tabs",dv.tag+'<a class="tag kj" href="/osc" target="_blank">OSC MON &rsaquo;</a><a class="tag kj" href="/autosave" target="_blank">AUTOSAVE &rsaquo;</a><a class="tag kj" href="/network" target="_blank">NETWORK &rsaquo;</a><a class="tag kj" href="/interfaces" target="_blank" style="color:#64d2ff;border-color:#64d2ff">NETWORK INTERFACES'+(ns.configured?'':' (SET!)')+' &rsaquo;</a>');
    setH("defwhy",dv.why);
    var ad=s.advice||{stage:0};
    setH("adv",ad.stage?'<div class="advb s'+ad.stage+'"><b>'+esc(ad.title)+'</b><span>'+esc(ad.text)+'</span></div>':"");
    var dk=y.dsk||{},DC={0:"#7a4300",1:"#39ff88",2:"#ffd60a",3:"#ff2d2d"};
    setH("tags",tg+(dk.free!=null?tag("DISK FREE:"+(dk.free>=1000?(dk.free/1000).toFixed(1)+"TB":Math.round(dk.free)+"GB"),DC[dk.flv||0]):"")+(y.used!=null?tag("MEM "+y.used+"/"+y.total+"GB"):"")
      );
    var cc=y.cpu==null?"#7a4300":lvl(y.cpu), rc=y.ram==null?"#7a4300":lvl(y.ram);
    var sf=s.self||{}, sd=sf.cpu==null?"#7a4300":lvl(sf.cpu);
    document.getElementById("nodes").innerHTML=
      node(y.cpu==null?"--":Math.round(y.cpu)+"%","CPU",cc,y.cpu>=90)
     +node(y.ram==null?"--":Math.round(y.ram)+"%","RAM",rc,y.ram>=90)
     +node(sf.cpu==null?"--":sf.cpu.toFixed(1)+"%",(sf.mb==null?"--":(sf.mb<1024?Math.round(sf.mb)+"MB":(sf.mb/1024).toFixed(2)+"GB")),sd,false,"endurance app");
    var nde=document.getElementById("nodes");nde.style.zoom="";if(nde.clientWidth&&nde.clientWidth<262)nde.style.zoom=(nde.clientWidth/262).toFixed(3);   // narrow screen + big zoom: the three hexagons shrink together, shape unchanged
    var sh=s.mode==="show";
    document.getElementById("modeln").innerHTML='OPERATIONAL MODE &middot; <b style="color:'+(sh?"#ffd60a":"#39ff88")+'">'+(sh?"SHOW":"EDIT")+'</b>';
    var hs=ws.map(function(w){return w.name}).join(" / ")||"---";
    var rl=s.roles||{};
    function rb(r){return r?'<b style="color:'+(r==="main"?"#39ff88":"#ffd60a")+'">['+r.toUpperCase()+']</b> ':""}
    var nt=(s.net||[]).map(function(a){
      return '<div class="nr"><span class="nn">'+esc(String(a.name).replace(/ ?\\(.*\\)/,''))+(a.kind&&String(a.name).toLowerCase().replace(/[^a-z]/g,'').indexOf(a.kind.toLowerCase().replace(/[^a-z]/g,''))<0?' &middot; '+esc(a.kind):'')+'</span><span class="nu">'+esc(a.ip)+':'+(s.port||8080)+'</span><span class="nq" style="color:#39ff88">'+rb(rl.self)+esc(hs)+'</span></div>'}).join("");
    if(!(s.net||[]).length)nt='<div class="nr"><span class="nn">HOST</span><span class="nu">'+esc(s.host_name||"")+'</span><span class="nq" style="color:#ff2d2d">'+rb(rl.self)+'NO IP</span></div>';
    (s.watchers||[]).forEach(function(w){nt+='<div class="pull" style="color:'+PC+'">BEING MONITORED BY ENDURANCE - '+esc(w)+'</div>'});
    nt+=pe.map(function(p){
      var pl=(s.pull||{})[p.ip],on=!!pl,inf="";
      if(on){
        if(pl.ok){var lc=DEFCOL[pl.lv]||PC;
          inf='<span style="color:'+PC+'">CPU '+(pl.cpu==null?"--":Math.round(pl.cpu)+"%")+' &middot; RAM '+(pl.ram==null?"--":Math.round(pl.ram)+"%")+' &middot; SWAP '+(pl.swap==null?"--":pl.swap.toFixed(1)+"GB")+'</span> <b style="color:'+lc+'">DEFCON '+(pl.lv||"--")+'</b>'}
        else inf=pl.ok===false?'<span style="color:#ff8a00">no Endurance answering on this Mac</span>':'<span style="color:#7a4300">waiting...</span>'}
      return '<div class="nr" style="color:'+PC+'"><span class="nn" style="color:'+PC+'">'+esc(p.host||"MAC")+'</span><span class="nu" style="color:'+PC+'">'+esc(p.ip)+'</span><a class="tag" href="#" style="font-size:7px;padding:0 3px;align-self:center;color:#39ff88;border-color:#39ff88" data-ip="'+esc(p.ip)+'" onclick="callB(this);return false">CALL</a><span class="nq">'+rb(p.role)+esc(p.workspaces.join(" / ")||"---")+'</span></div>'
        +'<div class="pull"><a class="tag" href="#" style="color:'+(on?"#39ff88":"#7a4300")+';border-color:'+(on?"#39ff88":"#7a4300")+'" data-ip="'+esc(p.ip)+'" data-on="'+(on?0:1)+'" onclick="pullB(this);return false">PULL INFO: '+(on?"ON":"OFF")+'</a>'+inf+'</div>'}).join("");
    document.getElementById("net").innerHTML=nt||'<div class="empty">NO NETWORK</div>';
    var pr=y.pressure;
    var pc=pr==null?"#7a4300":pr<=1?"#39ff88":pr==2?"#ffd60a":"#ff2d2d";
    var pl=pr==null?"---":pr<=1?"NORMAL":pr==2?"WARN":"CRITICAL";
    var tc=y.temp==null?null:(y.temp>=85?"#ff2d2d":y.temp>=72?"#ff8a00":"#39ff88"), bt=y.batt;
    var bc=!bt?null:bt.src==="BATT"?(bt.pct<=15?"#ff2d2d":bt.pct<=30?"#ffd60a":"#ff8a00"):"#39ff88";
    setH("memtags",tag("MEM PRSSR:"+pl,pc)
      +(y.swap!=null?tag("SWAP:"+y.swap.toFixed(1)+"GB",swapcol(y.swap)):"")
      +('<a class="tag" href="/disk" target="_blank" style="color:'+DC[dk.lv||0]+';border-color:'+DC[dk.lv||0]+'">DISK STATS &rsaquo;</a>')
      +(tc?tag("CPU TEMP:"+Math.round(y.temp)+"\u00b0C",tc):"")
      +(bt?tag("BATT:"+bt.pct+"% "+(bt.src==="BATT"?"BAT":"AC"),bc):""));
    fitRow("memtags");fitRow("tabs");
    document.getElementById("cores").innerHTML=coreHtml(y);
    var er=y.apps_err||y.sys_err;
    var kp=s.key_pats||[];
    var ap=(y.apps||[]).filter(function(p){var n=String(p.name).toLowerCase().replace(/[^a-z0-9]/g,"");   // the key app has its own row: not repeated
      return !kp.some(function(k){return n===k||(k.length>=3&&n.indexOf(k)>=0)})}).map(function(p){var c=appcol(p.name);
      return '<div class="ar" style="--c:'+c+'"><i></i><span class="an">'+esc(p.name)
        +'</span><span class="as">'+p.cpu.toFixed(1)+'% <b>|</b> '+(p.gb<1?Math.round(p.gb*1024)+'MB':p.gb.toFixed(2)+'GB')+'</span></div>'}).join("");
    var ky=y.key, kr="";
    if(s.key_app){
      var kn=esc(s.key_name||s.key_app).toUpperCase();
      kr='<div class="ar" style="--c:'+(ky&&ky.running?"#bf5af2":"#ffd60a")+'"><i></i><span class="an">KEY APP &middot; '+kn+(s.key_beta?' (BETA)':'')+'</span><span class="as">'
        +(ky&&ky.running?(ky.cpu.toFixed(1)+'% <b>|</b> '+(ky.gb<1?Math.round(ky.gb*1024)+'MB':ky.gb.toFixed(2)+'GB')):'NOT RUNNING')+'</span></div>'}
    var k2=y.key2;
    if(s.key_name&&k2){
      kr='<div class="ar" style="--c:'+(ky&&ky.running?"#bf5af2":"#ffd60a")+'"><i></i><span class="an">KEY APP &middot; QLAB</span><span class="as">'
        +(ky&&ky.running?(ky.cpu.toFixed(1)+'% <b>|</b> '+(ky.gb<1?Math.round(ky.gb*1024)+'MB':ky.gb.toFixed(2)+'GB')):'NOT RUNNING')+'</span></div>'
        +'<div class="ar" style="--c:'+(k2.running?"#bf5af2":"#ffd60a")+'"><i></i><span class="an">KEY APP &middot; LIVE PROFESSOR</span><span class="as">'
        +(k2.running?(k2.cpu.toFixed(1)+'% <b>|</b> '+(k2.gb<1?Math.round(k2.gb*1024)+'MB':k2.gb.toFixed(2)+'GB')):'NOT RUNNING')+'</span></div>'}
    setH("keyrow",kr);
    if(er)ap='<div class="err">error: '+esc(er)+'</div>'+ap;
    if(!ap)ap='<div class="empty">NO ACTIVE APP</div>';
    document.getElementById("apps").innerHTML=ap;
    setH("kdt","Key app in details"+(s.key_label?" &middot; "+esc(s.key_label)+(s.key_beta?" (beta)":""):""));
    setH("list",detailsHtml(s));
    callHtml(s);
  }).catch(function(e){tbusy=0;applyBlink()});
}
document.addEventListener("visibilitychange",function(){if(!document.hidden){lastOk=Date.now();tbusy=0;tick()}});
if(location.search.indexOf("app=1")>=0){document.documentElement.className="app";
  var sb=document.getElementById("stop"),armed=false;
  sb.onclick=function(){
    if(!armed){armed=true;sb.textContent="Confirm stop?";
      setTimeout(function(){armed=false;sb.textContent="Stop"},3000);return}
    sb.textContent="Stopping...";fetch("/stop",{method:"POST"}).catch(function(){});
  };
}
setInterval(tick,250);tick();
</script></body></html>"""


# ---- OSC: OSC message monitor (UDP, IPv4) ----
# The capture is done by tcpdump, started from the app window with the administrator password (root is needed to
# read the packets). tcpdump already filters in the kernel only the datagrams starting with "/" or "#bundle" and
# writes them to a pipe in /tmp/endurance-osc; here it is drained every OSC_SECONDS seconds and the last OSC_MAX are kept.
OSC_DIR = "/tmp/endurance-osc"
OSC_MAX = 30
OSC_SECONDS = 2.0
osc_log = deque(maxlen=OSC_MAX)
osc_info = {"ifaces": [], "err": None, "found": False}
_PCAP_MAGIC = {b"\xd4\xc3\xb2\xa1": "<", b"\xa1\xb2\xc3\xd4": ">", b"\x4d\x3c\xb2\xa1": "<", b"\xa1\xb2\x3c\x4d": ">"}


def _osc_arg_text(args):
    return " ".join(("%g" % a) if isinstance(a, float) else str(a) for a in args)


def osc_from_payload(p):
    """OSC messages (address, arguments) of a UDP datagram; it also reads bundles."""
    out = []

    def walk(b, depth=0):
        if len(out) >= 8:
            return
        if b[:1] == b"/":
            try:
                a, args = osc_decode(b)
            except Exception:
                try:
                    a, args = _read_str(b, 0)[0], []
                except Exception:
                    return
            out.append((a, _osc_arg_text(args)))
        elif b[:8] == b"#bundle\0" and depth < 3:
            i = 16
            while i + 4 <= len(b) and len(out) < 8:
                n = struct.unpack(">I", b[i:i + 4])[0]
                i += 4
                if n <= 0:
                    break
                walk(b[i:i + n], depth + 1)
                i += n

    walk(p)
    return out


def osc_ip_udp(link, d):
    """Da un frame catturato: (ip sorgente, porta sorgente, ip destinazione, porta destinazione, dati) se e' UDP/IPv4."""
    if link == 1:                      # Ethernet / Wi-Fi
        if len(d) < 14:
            return None
        et, off = d[12:14], 14
        if et == b"\x81\x00":
            et, off = d[16:18], 18
        if et != b"\x08\x00":
            return None
    elif link == 0:                    # loopback (lo0)
        off = 4
    elif link in (12, 101, 228):       # IP grezzo
        off = 0
    else:
        return None
    ip = d[off:]
    if len(ip) < 28 or ip[0] >> 4 != 4 or ip[9] != 17:
        return None
    if struct.unpack(">H", ip[6:8])[0] & 0x1fff:   # frammento successivo al primo
        return None
    u = ip[(ip[0] & 15) * 4:]
    if len(u) < 8:
        return None
    sport, dport, ulen = struct.unpack(">HHH", u[:6])
    return socket.inet_ntoa(ip[12:16]), sport, socket.inet_ntoa(ip[16:20]), dport, u[8:max(8, ulen)]


class OscPipe:
    def __init__(self, name):
        self.name = name
        self.path = os.path.join(OSC_DIR, name + ".pcap")
        self.fd = None
        self.live = False
        self.reset()

    def reset(self):
        self.buf = b""
        self.hdr = False
        self.end = "<"
        self.link = 0 if self.name.startswith("lo") else 1

    def close(self):
        if self.fd is not None:
            try:
                os.close(self.fd)
            except OSError:
                pass
            self.fd = None


def osc_drain(pp):
    """Reads what tcpdump has written since last time and adds the OSC messages found to the log."""
    if pp.fd is None:
        pp.fd = os.open(pp.path, os.O_RDONLY | os.O_NONBLOCK)
    got, eof = 0, False
    while got < (1 << 20):
        try:
            chunk = os.read(pp.fd, 65536)
        except BlockingIOError:
            break
        if not chunk:                  # no process is writing (tcpdump stopped)
            eof = True
            break
        pp.buf += chunk
        got += len(chunk)
    pp.live = not eof
    buf, i = pp.buf, 0
    if not pp.hdr and len(buf) >= 4:
        e = _PCAP_MAGIC.get(buf[:4])
        if e:
            if len(buf) < 24:
                return
            pp.end = e
            pp.link = struct.unpack(e + "I", buf[20:24])[0]
            i = 24
        pp.hdr = True                  # no header (reader restarted): default values
    n = 0
    while pp.hdr and len(buf) - i >= 16 and n < 3000:
        ts, _tu, incl, _orig = struct.unpack(pp.end + "IIII", buf[i:i + 16])
        if incl > 262144:              # out of alignment: restart from the next useful packet
            buf, i, pp.hdr = b"", 0, False
            break
        if len(buf) - i - 16 < incl:
            break
        r = osc_ip_udp(pp.link, buf[i + 16:i + 16 + incl])
        i += 16 + incl
        n += 1
        if r:
            src, sport, dst, dport, payload = r
            t = time.strftime("%H:%M:%S", time.localtime(ts))
            for addr, args in osc_from_payload(payload):
                osc_log.append({"t": t, "addr": addr[:90], "args": args[:70], "src": src, "sport": sport,
                                "dst": dst, "port": dport, "if": pp.name})
    pp.buf = buf[i:] if len(buf) - i < (4 << 20) else b""
    if eof:
        pp.reset()


osc_ctl = {"enabled": False}
osc_lock = threading.Lock()


def osc_set(enabled, devs=()):
    """Enables/disables the OSC monitor. It is always off at startup. When enabled the pipes are created (as the user);
    then the app window starts tcpdump (with the administrator password), which writes into them."""
    if enabled and show_mode():
        return False
    with osc_lock:
        osc_log.clear()
        shutil.rmtree(OSC_DIR, ignore_errors=True)
        osc_info["ifaces"], osc_info["found"], osc_info["err"] = [], False, None
        if not enabled:
            osc_ctl["enabled"] = False
            return True
        try:
            os.makedirs(OSC_DIR, exist_ok=True)
            try:
                os.chmod(OSC_DIR, 0o777)
            except OSError:
                pass
            for d in devs:
                if re.fullmatch(r"[a-z]+[0-9]+", d) and net_monitored(d):
                    path = os.path.join(OSC_DIR, d + ".pcap")
                    os.mkfifo(path, 0o666)
                    os.chmod(path, 0o666)
        except Exception as e:
            osc_info["err"] = repr(e)[:100]
            return False
        osc_ctl["enabled"] = True
        return True


def osc_loop():
    pipes = {}
    while True:
        try:
            with osc_lock:
                names = []
                if osc_ctl["enabled"] and os.path.isdir(OSC_DIR):
                    names = [f[:-5] for f in os.listdir(OSC_DIR) if f.endswith(".pcap")]
                for n in names:
                    if n not in pipes:
                        pipes[n] = OscPipe(n)
                for n in [k for k in pipes if k not in names]:
                    pipes.pop(n).close()
                for pp in list(pipes.values()):
                    try:
                        osc_drain(pp)
                    except OSError:
                        pp.close()
                        pp.live = False
                osc_info["found"] = bool(names)
                osc_info["ifaces"] = [pp.name for pp in pipes.values() if pp.live]
        except Exception as e:
            osc_info["err"] = repr(e)[:100]
        time.sleep(OSC_SECONDS)


def osc_state():
    return {"enabled": osc_ctl["enabled"], "live": osc_ctl["enabled"] and bool(osc_info["ifaces"]), "found": osc_info["found"], "ifaces": osc_info["ifaces"],
            "err": osc_info["err"], "max": OSC_MAX, "seconds": OSC_SECONDS, "log": list(osc_log)[::-1],
            "version": VERSION}


def mem_report():
    """Lines for the app window (RAM purge): memory, pressure, swap and the apps using the most RAM."""
    try:
        used, total = mem_stats()
    except Exception:
        return
    try:
        pr = {1: "normal", 2: "warning", 4: "critical"}.get(mem_pressure(), "?")
    except Exception:
        pr = "?"
    try:
        sw = swap_used_gb()
    except Exception:
        sw = 0.0
    print("MEM|%.1f|%.1f|%s|%.2f" % (used, total, pr, sw))
    agg = {}
    for line in run(["ps", "-axo", "rss=,comm="]).splitlines():
        parts = line.split(None, 1)
        if len(parts) == 2 and parts[0].isdigit():
            k = app_name(parts[1].strip())
            agg[k] = agg.get(k, 0) + int(parts[0]) / 1048576
    for k, v in sorted(agg.items(), key=lambda kv: kv[1], reverse=True)[:5]:
        print("APP|%s|%.2f" % (k, v))


AUTOSAVE_PAGE = """<!doctype html>
<html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<title>Workspace autosave</title>
<style>
  :root{--or:#ff8a00;--dim:#7a4300;--gr:#39ff88;--rd:#ff2d2d}
  html{-webkit-text-size-adjust:100%}
  html,body{margin:0;background:#000;color:var(--or);font-family:"Endurance Sans","DejaVu Sans Condensed","Helvetica Neue",Arial,sans-serif}
  body{padding:env(safe-area-inset-top) 12px calc(env(safe-area-inset-bottom) + 30px);max-width:520px;margin:0 auto}
  /*FONT*/
  .serif{font-family:"Endurance Serif","Hiragino Mincho ProN","Yu Mincho",Georgia,"Times New Roman",serif;font-weight:900}
  .head{display:flex;align-items:center;justify-content:center;gap:12px;padding:12px 0 6px}
  .head svg{width:40px;height:40px;flex:none}
  .title{font-size:17px;line-height:1;letter-spacing:.06em;text-transform:uppercase}
  .tags{display:flex;flex-wrap:wrap;justify-content:center;gap:4px;margin:2px 0 8px}
  .tag{border:1px solid var(--or);padding:1px 5px;font-size:10px;letter-spacing:.06em;text-transform:uppercase;white-space:nowrap;color:var(--or);text-decoration:none}
  .tag.on{color:var(--gr);border-color:var(--gr)}
  .sec{display:flex;align-items:center;gap:8px;margin:14px 0 6px;font-size:10px;letter-spacing:.2em;text-transform:uppercase}
  .sec i{flex:1;height:1px;background:var(--or);opacity:.45}
  .auto{display:flex;align-items:center;gap:8px;flex-wrap:wrap;font-size:10px;letter-spacing:.06em;text-transform:uppercase;padding:6px 0}
  .auto label{display:flex;align-items:center;gap:6px;cursor:pointer}
  .auto input[type=checkbox]{accent-color:#ff8a00;width:14px;height:14px;margin:0}
  .auto input[type=number]{width:46px;background:#000;border:1px solid var(--or);color:var(--or);font:inherit;font-size:11px;text-align:right;padding:2px 4px;border-radius:0}
  .info{font-size:9px;line-height:1.7;letter-spacing:.06em;text-transform:uppercase;color:var(--dim);padding:2px 0}
  .info b{color:var(--or);font-weight:400}
  .info .gr{color:var(--gr)}
  .info .bad{color:var(--rd)}
  .note{font-size:8px;line-height:1.5;letter-spacing:.04em;color:var(--dim);padding:10px 0}
  .credit{margin:22px 0 4px;font-size:5.5px;letter-spacing:.1em;text-transform:uppercase;color:var(--dim)}
</style></head><body>
<div class="head"><svg viewBox="0 0 40 40" fill="none" stroke="#ff8a00" stroke-width="1.5" stroke-linejoin="round"><circle cx="20" cy="20" r="18" stroke-width="1.3"/><g transform="translate(19.6 20.6) scale(0.032) translate(-600 -532)" stroke-linejoin="round" stroke-linecap="round" fill="none"><path d="M640 130 C705 130 760 150 790 178 L928 215 L800 258 L765 298 L730 322 C790 345 832 450 832 620 L830 800 L782 932 L470 932 L276 750 C275 600 330 420 440 330 C470 290 475 235 520 185 C560 148 600 130 640 130 Z" fill="#000" stroke="#000" stroke-width="75"/><path d="M640 130 C705 130 760 150 790 178 L928 215 L800 258 L765 298 L730 322 C790 345 832 450 832 620 L830 800 L782 932 L470 932 L276 750 C275 600 330 420 440 330 C470 290 475 235 520 185 C560 148 600 130 640 130 Z" stroke="#ff8a00" stroke-width="42.1875" fill="#000"/><path d="M725 328 C610 335 565 440 556 530 C552 620 570 650 566 700 L512 826 L428 862 L455 716 L405 590 C440 480 500 400 560 350 C610 316 670 318 725 328 Z" stroke="#ff8a00" stroke-width="42.1875"/><path d="M790 178 L742 218 L800 258 M742 226 L920 214" stroke="#ff8a00" stroke-width="42.1875"/></g></svg>
<div class="title serif">Workspace autosave</div></div>
<div class="tags"><a class="tag" href="/">&lsaquo; The Endurance</a><span class="tag" id="st">---</span></div>
<div class="sec"><span>Autosave</span><i></i></div>
<div class="auto"><label><input type="checkbox" id="asOn" disabled><span>all qlab workspaces autosave</span></label>
<span>every <input type="number" id="asMin" min="1" max="120" step="1" value="5" disabled> min</span></div>
<div class="info" id="asInfo"></div>
<div class="note" id="asNote">Sends the Save command (like Cmd+S) to every QLab workspace open on the network. Always off when The Endurance starts; the interval is remembered. A workspace protected by an OSC passcode cannot be saved this way.</div>
<div class="credit serif">crafted by Francesco Lo Brano</div>
<script>
function esc(x){return String(x).replace(/[&<>"]/g,function(c){return{"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]})}
function pad(n){return (n<10?"0":"")+n}
function fmt(s){s=Math.max(0,s);var m=Math.floor(s/60),x=Math.floor(s%60);return pad(m)+":"+pad(x)}
function hhmmss(t){var d=new Date(t*1000);return pad(d.getHours())+":"+pad(d.getMinutes())+":"+pad(d.getSeconds())}
var busyAt=0, inited=false;
function send(){
  var on=document.getElementById("asOn").checked, m=parseFloat(document.getElementById("asMin").value);
  if(!isFinite(m)||m<1)m=5; if(m>120)m=120;
  busyAt=Date.now();
  fetch("/autosave?enabled="+(on?1:0)+"&minutes="+m,{method:"POST"}).catch(function(){});
}
var wired=false;
function render(a,now,local){
  var on=document.getElementById("asOn"), mi=document.getElementById("asMin");
  on.disabled=!local;mi.disabled=!local;
  if(local&&!wired){wired=true;on.onchange=send;mi.onchange=send}
  document.getElementById("asNote").innerHTML=(local?"You can change it here (this is the Mac itself) or in the app. ":"Read-only on this device: change it from the app or the browser of the Mac. ")+"Sends the Save command (like Cmd+S) to every QLab workspace open on the network. Always off when The Endurance starts; the interval is remembered. A workspace protected by an OSC passcode cannot be saved this way.";
  if(Date.now()-busyAt>2500){if(document.activeElement!==on)on.checked=!!a.enabled;if(document.activeElement!==mi)mi.value=a.minutes}
  var t=document.getElementById("st");t.textContent=a.enabled?"ACTIVE":"OFF";t.className="tag"+(a.enabled?" on":"");
  var h="";
  if(!a.enabled)h="Off";
  else{
    var nx=a.next&&a.next-now<=a.minutes*60+2?Math.max(0,Math.round(a.next-now)):null;
    if(!a.last)h="Waiting for the first save...";
    else{
      h="Last save <b>"+hhmmss(a.last)+"</b> &middot; <b>"+a.ok+"/"+a.total+"</b> workspaces";
      if(a.names&&a.names.length)h+='<br><span class="gr">Saved: '+a.names.map(esc).join(", ")+"</span>";
    }
    h+="<br>"+(nx!=null?"Next in <b>"+fmt(nx)+"</b>":"Saving...");
    if(a.err)h+='<br><span class="bad">'+esc(a.err)+"</span>";
  }
  document.getElementById("asInfo").innerHTML=h;
}
var busy=false;
function tick(){
  if(busy)return;busy=true;
  fetch("/autosavedata",{cache:"no-store"}).then(function(r){return r.json()}).then(function(s){busy=false;render(s.autosave||{},s.now||Date.now()/1000,!!s.local)}).catch(function(){busy=false;document.getElementById("st").textContent="OFFLINE"});
}
tick();setInterval(tick,1000);
</script></body></html>
"""


DEFCON_PAGE = """<!doctype html>
<html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<title>DEFCON log</title>
<style>
  :root{--or:#ff8a00;--dim:#7a4300;--gr:#39ff88;--rd:#ff2d2d}
  html{-webkit-text-size-adjust:100%}
  html,body{margin:0;background:#000;color:var(--or);font-family:"Endurance Sans","DejaVu Sans Condensed","Helvetica Neue",Arial,sans-serif}
  body{padding:env(safe-area-inset-top) 12px calc(env(safe-area-inset-bottom) + 24px);max-width:560px;margin:0 auto}
  /*FONT*/
  .serif{font-family:"Endurance Serif","Hiragino Mincho ProN","Yu Mincho",Georgia,"Times New Roman",serif;font-weight:900}
  .head{display:flex;align-items:center;justify-content:center;gap:12px;padding:12px 0 6px}
  .head svg{width:40px;height:40px;flex:none}
  .title{font-size:17px;line-height:1;letter-spacing:.06em;text-transform:uppercase}
  .tags{display:flex;flex-wrap:wrap;justify-content:center;gap:4px;margin:2px 0 8px}
  .tag{border:1px solid var(--or);padding:1px 5px;font-size:10px;letter-spacing:.06em;text-transform:uppercase;white-space:nowrap;color:var(--or);text-decoration:none;background:#000;font-family:inherit;cursor:pointer}
  .tag.on{color:var(--gr);border-color:var(--gr)}
  .tag.bad{color:var(--rd);border-color:var(--rd)}
  .sec{display:flex;align-items:center;gap:8px;margin:14px 0 6px;font-size:10px;letter-spacing:.2em;text-transform:uppercase}
  .sec i{flex:1;height:1px;background:var(--or);opacity:.45}
  .big{text-align:center;font-size:30px;letter-spacing:.1em;font-weight:700;margin:6px 0 0}
  .why{text-align:center;font-size:9px;letter-spacing:.08em;text-transform:uppercase;min-height:12px}
  .strip{display:flex;gap:1px;height:26px;margin:6px 0 2px}
  .strip i{flex:1;background:#1a0d00}
  .lbl{display:flex;justify-content:space-between;font-size:8px;color:var(--dim);letter-spacing:.06em}
  .ev{font-size:10px;line-height:1.6;letter-spacing:.04em;border-bottom:1px solid #2a1600;padding:3px 0}
  .ev b{font-weight:700}
  .ev span{color:var(--dim);display:block;font-size:9px}
  .empty{color:var(--dim);font-size:10px;padding:8px 0;text-transform:uppercase}
  .note{font-size:8px;line-height:1.5;letter-spacing:.04em;color:var(--dim);padding:8px 0}
  .credit{margin:22px 0 4px;font-size:5.5px;letter-spacing:.1em;text-transform:uppercase;color:var(--dim)}
</style></head><body>
<div class="head"><svg viewBox="0 0 40 40" fill="none" stroke="#ff8a00" stroke-width="1.5" stroke-linejoin="round"><circle cx="20" cy="20" r="18" stroke-width="1.3"/><g transform="translate(19.6 20.6) scale(0.032) translate(-600 -532)" stroke-linejoin="round" stroke-linecap="round" fill="none"><path d="M640 130 C705 130 760 150 790 178 L928 215 L800 258 L765 298 L730 322 C790 345 832 450 832 620 L830 800 L782 932 L470 932 L276 750 C275 600 330 420 440 330 C470 290 475 235 520 185 C560 148 600 130 640 130 Z" fill="#000" stroke="#000" stroke-width="75"/><path d="M640 130 C705 130 760 150 790 178 L928 215 L800 258 L765 298 L730 322 C790 345 832 450 832 620 L830 800 L782 932 L470 932 L276 750 C275 600 330 420 440 330 C470 290 475 235 520 185 C560 148 600 130 640 130 Z" stroke="#ff8a00" stroke-width="42.1875" fill="#000"/><path d="M725 328 C610 335 565 440 556 530 C552 620 570 650 566 700 L512 826 L428 862 L455 716 L405 590 C440 480 500 400 560 350 C610 316 670 318 725 328 Z" stroke="#ff8a00" stroke-width="42.1875"/><path d="M790 178 L742 218 L800 258 M742 226 L920 214" stroke="#ff8a00" stroke-width="42.1875"/></g></svg>
<div class="title serif">DEFCON log</div></div>
<div class="tags"><a class="tag" href="/">&lsaquo; The Endurance</a></div>
<div class="big" id="big">DEFCON --</div>
<div class="why" id="why"></div>
<div class="sec"><span>Last 60 minutes</span><i></i></div>
<div class="strip" id="strip"></div>
<div class="lbl"><span>-60 min</span><span>now</span></div>
<div class="sec"><span>What each level means</span><i></i></div>
<div id="leg">
<div class="ev"><b style="color:#39ff88">DEFCON 5</b> &middot; Normal<span>No risk.</span></div>
<div class="ev"><b style="color:#b6e63a">DEFCON 4</b> &middot; Watch<span>One reading is high. Nothing to do.</span></div>
<div class="ev"><b style="color:#ffd60a">DEFCON 3</b> &middot; Caution<span>Load is rising. Check the backup.</span></div>
<div class="ev"><b style="color:#ff8a00">DEFCON 2</b> &middot; Danger<span>Near the limit. Backup online, show open.</span></div>
<div class="ev"><b style="color:#ff2d2d">DEFCON 1</b> &middot; Critical<span>Crash or glitch imminent. Switch to the backup.</span></div>
</div>
<div class="sec"><span>Sensitivity</span><i></i></div>
<div class="tags" id="sens"></div>
<div class="note">Relaxed: later warnings. Strict: earlier warnings. Normal is tuned for a show machine.</div>
<div class="sec"><span>Export</span><i></i></div>
<div class="tags"><a class="tag" href="/defcon/export.pdf" target="_blank">Export PDF</a><a class="tag" href="/defcon/export.csv">Export CSV</a><button class="tag bad" id="clr">Clear log</button></div>
<div class="note" id="cnt"></div>
<div class="sec"><span>Key app</span><i></i></div>
<div class="note" id="keyi"></div>
<div class="sec"><span>Latest samples</span><i></i></div>
<div id="rec"></div>
<div class="sec"><span>DEFCON changes and crashes</span><i></i></div>
<div id="ev"></div>
<div class="credit serif">crafted by Francesco Lo Brano</div>
<script>
function esc(x){return String(x).replace(/[&<>"]/g,function(c){return{"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]})}
function pad(n){return (n<10?"0":"")+n}
function ts(t){var d=new Date(t*1000);return d.getFullYear()+"-"+pad(d.getMonth()+1)+"-"+pad(d.getDate())+" "+pad(d.getHours())+":"+pad(d.getMinutes())+":"+pad(d.getSeconds())}
function appsTxt(a){return (a&&a.length)?a.map(function(x){return x[0]+" "+x[1]+"%/"+x[2]+"GB"}).join(" · "):"-"}
function resTxt(r){var p=r.pr==null?"-":r.pr<=1?"normal":r.pr==2?"warn":"critical";
  return "CPU "+(r.cpu==null?"-":Math.round(r.cpu))+"% · RAM "+(r.ram==null?"-":Math.round(r.ram))+"% · pressure "+p+" · swap "+(r.swap==null?"-":r.swap.toFixed(1))+"GB · temp "+(r.temp==null?"-":Math.round(r.temp)+"C")+" · DEFCON "+(r.lv||"-")}
var COL={5:"#39ff88",4:"#b6e63a",3:"#ffd60a",2:"#ff8a00",1:"#ff2d2d"},SENS=["normal","strict"];
document.getElementById("sens").onclick=function(e){var v=e.target.getAttribute&&e.target.getAttribute("data-v");if(v)setSens(v)};
function setSens(v){fetch("/defcon/sens?value="+v,{method:"POST"}).then(tick).catch(function(){})}
document.getElementById("clr").onclick=function(){
  if(confirm("Delete the whole DEFCON log and data history?"))fetch("/defcon/clear",{method:"POST"}).then(tick).catch(function(){})};
function tick(){
  fetch("/defcondata",{cache:"no-store"}).then(function(r){return r.json()}).then(function(d){
    var f=d.defcon,c=COL[f.level];
    var b=document.getElementById("big");b.textContent="DEFCON "+f.level;b.style.color=c;
    var w=document.getElementById("why");w.textContent=f.level<5?(f.why||[]).join(" · "):"";w.style.color=c;
    document.getElementById("strip").innerHTML=d.strip.map(function(l){return '<i style="'+(l?'background:'+COL[l]:'')+'"></i>'}).join("");
    document.getElementById("sens").innerHTML=SENS.map(function(v){return '<button class="tag'+(f.sens===v?' on':'')+'" data-v="'+v+'">'+v+'</button>'}).join("");
    document.getElementById("cnt").textContent=d.samples+" samples logged"+(d.first?" since "+ts(d.first):"")+" (one every 10 s, kept on the Mac).";
    var k=d.key,kn=d.key_app;
    document.getElementById("keyi").innerHTML=kn?("Key app: <b>"+esc(kn)+"</b> &middot; "+(k&&k.running?("running &middot; CPU "+k.cpu+"% &middot; RAM "+(k.gb<1?Math.round(k.gb*1024)+"MB":k.gb.toFixed(2)+"GB")):"<span style='color:#ffd60a'>not running</span>")+" &middot; crashes logged: "+d.crashes+". Choose the key app in the desktop app (Menu &rsaquo; Key app). It is watched more closely: if it disappears, the crash is logged with the system resources of that moment."):"No key app selected.";
    document.getElementById("rec").innerHTML=(d.recent||[]).length?d.recent.map(function(m){
      return '<div class="ev"><b style="color:'+COL[m.lv]+'">DEFCON '+m.lv+'</b> &middot; '+ts(m.t)+'<span>CPU '+(m.cpu==null?"-":Math.round(m.cpu))+'% &middot; RAM '+(m.ram==null?"-":Math.round(m.ram))+'% &middot; apps: '+esc(appsTxt(m.apps))+'</span></div>'}).join(""):'<div class="empty">No samples yet</div>';
    document.getElementById("ev").innerHTML=d.events.length?d.events.map(function(e){
      if(e.type==="crash"||e.type==="closed"){
        var r=e.res||{};
        return '<div class="ev"><b style="color:#ff2d2d">'+(e.type==="crash"?"CRASH":"KEY APP CLOSED")+' &middot; '+esc(e.app)+(e.key?" (key app)":"")+'</b> &middot; '+ts(e.t)
          +'<span>'+(e.type==="crash"?"report: "+esc(e.report):"no crash report found (closed, or crashed without a report)")+'</span>'
          +'<span>at that moment: '+esc(resTxt(r))+' &middot; the app used '+e.app_cpu+'% / '+e.app_gb+'GB</span>'
          +'<span>apps in use: '+esc(appsTxt(e.apps))+'</span></div>'}
      return '<div class="ev"><b style="color:'+COL[e.to]+'">DEFCON '+e.from+' &rarr; '+e.to+'</b> &middot; '+ts(e.t)+'<span>'+esc((e.why||[]).join(" · ")||"-")+'</span>'
        +(e.apps&&e.apps.length?'<span>apps in use: '+esc(appsTxt(e.apps))+'</span>':'')+'</div>'}).join(""):'<div class="empty">No changes logged</div>';
  }).catch(function(){});
}
tick();setInterval(tick,3000);
</script></body></html>
"""


OSC_PAGE = """<!doctype html>
<html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<title>OSC monitor</title>
<style>
  :root{--or:#ff8a00;--dim:#7a4300;--gr:#39ff88}
  html{-webkit-text-size-adjust:100%}
  html,body{margin:0;background:#000;color:var(--or);font-family:"Endurance Sans","DejaVu Sans Condensed","Helvetica Neue",Arial,sans-serif}
  body{padding:env(safe-area-inset-top) 12px calc(env(safe-area-inset-bottom) + 30px);max-width:520px;margin:0 auto}
  /*FONT*/
  .serif{font-family:"Endurance Serif","Hiragino Mincho ProN","Yu Mincho",Georgia,"Times New Roman",serif;font-weight:900}
  .head{display:flex;align-items:center;justify-content:center;gap:12px;padding:12px 0 6px}
  .head svg{width:40px;height:40px;flex:none}
  .title{font-size:17px;line-height:1;letter-spacing:.06em;text-transform:uppercase}
  .jp{color:var(--dim);font-size:11px;letter-spacing:.1em}
  .tags{display:flex;flex-wrap:wrap;justify-content:center;gap:4px;margin:2px 0 8px}
  .tag{border:1px solid var(--or);padding:1px 5px;font-size:10px;letter-spacing:.06em;text-transform:uppercase;white-space:nowrap;color:var(--or);text-decoration:none}
  .sec{display:flex;align-items:center;gap:8px;margin:12px 0 6px;font-size:10px;letter-spacing:.2em;text-transform:uppercase}
  .sec i{flex:1;height:1px;background:var(--or);opacity:.45}
  .r{padding:3px 0;border-bottom:1px solid rgba(255,138,0,.22)}
  .l1{display:flex;gap:8px;align-items:baseline;font-size:9px}
  .tm{flex:none;color:var(--dim);font-variant-numeric:tabular-nums}
  .ad{flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:var(--or)}
  .ag{color:#fff}
  .l2{font-size:8px;color:var(--dim);letter-spacing:.04em;padding-left:56px;font-variant-numeric:tabular-nums}
  .l2 b{color:var(--gr);font-weight:400}
  .msg{font-size:9px;line-height:1.5;color:var(--dim);padding:6px 0;letter-spacing:.04em}
  .err{color:#ff2d2d}
  .credit{position:fixed;left:12px;bottom:calc(env(safe-area-inset-bottom) + 8px);font-size:5.5px;letter-spacing:.1em;text-transform:uppercase;color:var(--dim);background:#000;padding:2px 6px 2px 0}
</style></head><body>
<div class="head"><svg viewBox="0 0 40 40" fill="none" stroke="#ff8a00" stroke-width="1.5" stroke-linejoin="round"><circle cx="20" cy="20" r="18" stroke-width="1.3"/><g transform="translate(19.6 20.6) scale(0.032) translate(-600 -532)" stroke-linejoin="round" stroke-linecap="round" fill="none"><path d="M640 130 C705 130 760 150 790 178 L928 215 L800 258 L765 298 L730 322 C790 345 832 450 832 620 L830 800 L782 932 L470 932 L276 750 C275 600 330 420 440 330 C470 290 475 235 520 185 C560 148 600 130 640 130 Z" fill="#000" stroke="#000" stroke-width="75"/><path d="M640 130 C705 130 760 150 790 178 L928 215 L800 258 L765 298 L730 322 C790 345 832 450 832 620 L830 800 L782 932 L470 932 L276 750 C275 600 330 420 440 330 C470 290 475 235 520 185 C560 148 600 130 640 130 Z" stroke="#ff8a00" stroke-width="42.1875" fill="#000"/><path d="M725 328 C610 335 565 440 556 530 C552 620 570 650 566 700 L512 826 L428 862 L455 716 L405 590 C440 480 500 400 560 350 C610 316 670 318 725 328 Z" stroke="#ff8a00" stroke-width="42.1875"/><path d="M790 178 L742 218 L800 258 M742 226 L920 214" stroke="#ff8a00" stroke-width="42.1875"/></g></svg>
<div class="title serif">OSC monitor</div></div>
<div class="tags"><a class="tag" href="/">&lsaquo; The Endurance</a><span class="tag" id="st">---</span></div>
<div class="sec"><span>OSC log</span><i></i><span id="cnt"></span></div>
<div id="info"></div>
<div id="log"></div>
<div class="credit serif">crafted by Francesco Lo Brano</div>
<script>
function esc(x){return String(x).replace(/[&<>"]/g,function(c){return{"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]})}
var busy=false;
function tick(){
  if(busy)return;busy=true;
  fetch("/oscdata",{cache:"no-store"}).then(function(r){return r.json()}).then(function(s){
    busy=false;
    var st=document.getElementById("st");
    st.textContent=s.live?("monitor active \\u00b7 "+s.ifaces.join(", ")):(s.enabled?"starting capture...":"monitor off");
    st.style.color=s.live?"#39ff88":(s.enabled?"#ffd60a":"#ff2d2d");st.style.borderColor=st.style.color;
    var info="";
    if(!s.enabled){info='<div class="msg">The OSC monitor is not active. On the Mac open the window of The Endurance and go to the <b>OSC MON</b> tab: press Enable (it asks for the administrator password).</div>'}else if(!s.live){info='<div class="msg">Waiting for the capture to start...</div>'}
    if(s.err){info+='<div class="msg err">'+esc(s.err)+'</div>'}
    document.getElementById("info").innerHTML=info;
    document.getElementById("cnt").textContent=s.log.length+"/"+s.max;
    document.getElementById("log").innerHTML=s.log.map(function(e){
      return '<div class="r"><div class="l1"><span class="tm">'+esc(e.t)+'</span><span class="ad">'+esc(e.addr)+(e.args?' <span class="ag">'+esc(e.args)+'</span>':'')+'</span></div>'
        +'<div class="l2">&rarr; <b>'+esc(e.dst)+':'+e.port+'</b> &middot; da '+esc(e.src)+':'+e.sport+'</div></div>'}).join("");
  }).catch(function(){busy=false;var st=document.getElementById("st");st.textContent="the endurance is not responding";st.style.color="#ff2d2d"});
}
setInterval(tick,2000);tick();
</script></body></html>"""


DISK_PAGE = (DEFCON_PAGE[:DEFCON_PAGE.index("</style>")].replace("<title>DEFCON log</title>", "<title>Disk stats</title>") + """
  .tiles{display:flex;gap:6px;margin:8px 0}
  .tile{flex:1;border:1px solid var(--or);text-align:center;padding:6px 2px}
  .tile b{display:block;font-size:20px;letter-spacing:.04em;font-weight:700}
  .tile span{font-size:8px;letter-spacing:.14em;text-transform:uppercase;color:var(--dim)}
  .card{border:1px solid var(--dim);padding:7px 8px;margin:7px 0}
  .card .h{display:flex;justify-content:space-between;gap:8px;font-size:12px;letter-spacing:.06em;text-transform:uppercase}
  .card .h b{font-weight:700;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
  .card .s{font-size:9px;letter-spacing:.06em;text-transform:uppercase;color:var(--dim);margin-top:3px;line-height:1.6}
  .card .s i{font-style:normal;color:var(--or)}
  .bar{height:5px;background:#1a0d00;margin:5px 0 2px}
  .bar div{height:100%}
</style></head><body>
""" + DEFCON_PAGE[DEFCON_PAGE.index('<div class="head">'):DEFCON_PAGE.index('<div class="title serif">')] + """<div class="title serif">Disk stats</div></div>
<div class="tags"><a class="tag" href="/">&lsaquo; The Endurance</a></div>
<div class="big" id="big">DISK --</div>
<div class="tiles" id="tiles"></div>
<div class="sec"><span>Volumes</span><i></i></div>
<div id="vols"></div>
<div class="sec"><span id="kt">Key app</span><i></i></div>
<div class="note" id="key"></div>
<div class="note" id="lim"></div>
<div class="credit serif">crafted by Francesco Lo Brano</div>
<script>
function esc(x){return String(x).replace(/[&<>"]/g,function(c){return{"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]})}
var C={0:"#7a4300",1:"#39ff88",2:"#ffd60a",3:"#ff2d2d"},T={0:"--",1:"OK",2:"WATCH",3:"ACT"};
function mb(v){return v==null?"--":(v>=100?Math.round(v):v.toFixed(1))+" MB/s"}
function gb(v){return v==null?"--":v>=1000?(v/1000).toFixed(2)+" TB":Math.round(v)+" GB"}
function tick(){
  fetch("/diskdata",{cache:"no-store"}).then(function(r){return r.json()}).then(function(d){
    var s=d.sys||{},lv=s.lv||0,b=document.getElementById("big");
    b.textContent="DISK "+T[lv];b.style.color=C[lv];
    function tile(v,l,c){return '<div class="tile" style="border-color:'+c+'"><b style="color:'+c+'">'+v+'</b><span>'+l+'</span></div>'}
    document.getElementById("tiles").innerHTML=tile(mb(s.r),"read",C[1])+tile(mb(s.w),"write",C[1])
      +tile(s.lat==null?"--":(s.lat<10?s.lat.toFixed(1):Math.round(s.lat))+" ms","latency",C[s.llv==null?0:s.llv]);
    document.getElementById("vols").innerHTML=(d.vols||[]).length?d.vols.map(function(v){
      var col=(v.boot||v.used)?C[v.flv]:"#ff8a00",pc=v.total?Math.max(0,Math.min(100,100-v.free/v.total*100)):0;
      var sm=v.slv===3?'<i style="color:'+C[3]+'">SMART FAILING</i>':v.slv===1?'<i style="color:'+C[1]+'">SMART OK</i>':'SMART n/a';
      return '<div class="card"><div class="h"><b>'+esc(v.name)+'</b><span style="color:'+col+'">'+gb(v.free)+' free</span></div>'
        +'<div class="bar"><div style="width:'+pc+'%;background:'+col+'"></div></div>'
        +'<div class="s">'+(v.internal?"internal":"external"+(v.bus?" "+esc(v.bus):""))+' &middot; '+(v.ssd?"SSD":"HDD")+' &middot; '+sm+'</div>'
        +'<div class="s">read <i>'+mb(v.r)+'</i> &middot; write <i>'+mb(v.w)+'</i> &middot; latency <i style="color:'+C[v.llv||0]+'">'+(v.lat==null?"--":v.lat+" ms")+'</i></div>'
        +(v.used||v.files?'<div class="s"><i>'+esc(d.key_app||"Key app")+'</i> uses this disk'+(v.files?' &middot; '+v.files+' open files':'')+'</div>':'')+'</div>'}).join(""):'<div class="empty">No disk data yet</div>';
    var k=d.key,kn=esc(d.key_app||"");
    document.getElementById("kt").textContent=kn?kn:"Key app";
    document.getElementById("key").innerHTML=!kn?"No key app chosen (DEFCON page).":!d.key_running?kn+": not running."
      :(k?("Read <b>"+mb(k.r)+"</b> &middot; write <b>"+mb(k.w)+"</b>"+(k.share==null?"":" &middot; "+k.share+"% of disk traffic")):"Reading...")+(d.show?"<br>SHOW mode: the open-files check is off.":"");
    var L=d.limits||{free:[20,10],pct:[10,5],ssd:[10,40],hdd:[40,100]};
    document.getElementById("lim").innerHTML="Free space: yellow below "+L.free[0]+" GB or "+L.pct[0]+"%, red below "+L.free[1]+" GB or "+L.pct[1]+"%. Latency SSD: yellow from "+L.ssd[0]+" ms, red from "+L.ssd[1]+" ms. HDD: "+L.hdd[0]+" / "+L.hdd[1]+" ms. The color counts for the boot disk and the disks the key app uses; the others are info.";
  }).catch(function(){});
}
tick();setInterval(tick,5000);
</script></body></html>
""")

IFACES_PAGE = (DEFCON_PAGE[:DEFCON_PAGE.index("</style>")].replace("<title>DEFCON log</title>", "<title>Network interfaces</title>") + """
  .big.if{font-size:20px;letter-spacing:.12em}
  .expl{border:1px solid #64d2ff;color:#64d2ff;padding:6px 8px;margin:8px 0;font-size:10px;line-height:1.55;letter-spacing:.05em;text-transform:uppercase}
  .expl b{font-weight:700}
  .ifr{display:flex;align-items:center;gap:10px;border:1px solid var(--dim);padding:7px 8px;margin:6px 0;cursor:pointer;background:#000;color:var(--or);font:inherit;width:100%;text-align:left}
  .ifr.on{border-color:var(--gr)}
  .ifr.ro{cursor:default}
  .fl{flex:none;width:18px;height:18px;border:2px solid var(--dim);display:flex;align-items:center;justify-content:center;font-size:14px;line-height:1;color:#000}
  .ifr.on .fl{border-color:var(--gr);background:var(--gr)}
  .ifr .m{flex:1;min-width:0}
  .ifr .n{font-size:12px;letter-spacing:.06em;text-transform:uppercase;font-weight:700;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
  .ifr .a{font-size:9px;letter-spacing:.06em;text-transform:uppercase;color:var(--dim);margin-top:2px}
  .ifr .st{flex:none;font-size:9px;letter-spacing:.1em;text-transform:uppercase;color:var(--dim)}
  .ifr.on .st{color:var(--gr)}
  .ifr.off .n{color:var(--dim)}
  .warn{border:1px solid var(--ye);color:var(--ye);padding:6px 8px;margin:8px 0;font-size:10px;line-height:1.5;letter-spacing:.05em;text-transform:uppercase;text-align:center}
</style></head><body>
""" + DEFCON_PAGE[DEFCON_PAGE.index('<div class="head">'):DEFCON_PAGE.index('<div class="title serif">')] + """<div class="title serif">Network interfaces</div></div>
<div class="tags"><a class="tag" href="/">&lsaquo; The Endurance</a></div>
<div class="big if" id="big">PORTS --</div>
<div class="expl"><b>Ticked</b> = monitored: The Endurance scans, pings and answers on it.<br><b>Unticked</b> = left alone: nothing sent, nothing answers. Untick the Dante port.</div>
<div id="warn"></div>
<div id="list"></div>
<div class="tags" id="act"></div>
<div class="note" id="ro"></div>
<div class="credit serif">crafted by Francesco Lo Brano</div>
<script>
function esc(x){return String(x).replace(/[&<>"]/g,function(c){return{"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]})}
var LOCAL=false;
function post(u){return fetch(u,{method:"POST"}).then(tick).catch(function(){})}
document.getElementById("list").onclick=function(e){var b=e.target.closest(".ifr");if(!b||!LOCAL)return;
  post("/interfaces/set?dev="+encodeURIComponent(b.getAttribute("data-dev"))+"&on="+(b.getAttribute("data-on")==="1"?0:1))};
document.getElementById("act").onclick=function(e){if(e.target.id==="ok")post("/interfaces/confirm")};
function tick(){
  fetch("/interfacesdata",{cache:"no-store"}).then(function(r){return r.json()}).then(function(d){
    LOCAL=!!d.local;
    var big=document.getElementById("big");
    big.textContent=d.configured?(d.on+" OF "+d.active+" PORTS MONITORED"):"NOT SET";
    big.style.color=d.configured?"#39ff88":"#ffd60a";
    document.getElementById("warn").innerHTML=d.configured?"":'<div class="warn">Not set yet: all ports are used. Choose, then confirm.</div>';
    document.getElementById("list").innerHTML=(d.ifaces||[]).length?d.ifaces.map(function(i){
      return '<button class="ifr '+(i.on?"on":"off")+(LOCAL?"":" ro")+'" data-dev="'+esc(i.dev)+'" data-on="'+(i.on?1:0)+'"><span class="fl">'+(i.on?"&#10003;":"")+'</span>'
        +'<span class="m"><span class="n" style="display:block">'+esc(i.name)+' ('+esc(i.dev)+')</span><span class="a" style="display:block">'
        +(i.active?esc(i.ip)+(i.ll?" (no DHCP)":""):"not connected")+(i.new?" &middot; new":"")+'</span></span>'
        +'<span class="st">'+(i.on?"monitored":"left alone")+'</span></button>'}).join(""):'<div class="empty">No network ports found</div>';
    document.getElementById("act").innerHTML=(!d.configured&&LOCAL)?'<button class="tag on" id="ok">Confirm</button>':"";
    document.getElementById("ro").textContent=LOCAL?"":"Read only here: change it from the app or from a browser on this Mac.";
  }).catch(function(){});
}
tick();setInterval(tick,3000);
</script></body></html>
""")

# title font: Noto Serif CJK JP Black (SIL Open Font License), reduced to Latin letters and embedded
FONT_SANS_CSS = "@font-face{font-family:'Endurance Sans';font-weight:400;font-style:normal;src:url(data:font/woff;base64,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) format('woff')}@font-face{font-family:'Endurance Sans';font-weight:700;font-style:normal;src:url(data:font/woff;base64,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) format('woff')}"
OVER_CSS = "body *{letter-spacing:.04em}.title.serif{font-size:21px;transform:scaleX(.68);letter-spacing:.03em;margin:0 -22px;white-space:nowrap}.head{flex-wrap:wrap;row-gap:2px}.head .ver{margin-left:10px}"
FONT_CSS = "@font-face{font-family:'Endurance Serif';font-weight:900;font-style:normal;src:url(data:font/woff;base64,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) format('woff')}"
ZOOM_UI = '<div class="zm" id="zm" style="margin:14px 0 10px;text-align:center;font-size:9px;letter-spacing:.12em;text-transform:uppercase;color:#7a4300">ZOOM <a data-z="1">small</a> <a data-z="1.25">normal</a> <a data-z="1.5">big</a></div><style>.zm a{display:inline-block;border:1px solid #7a4300;color:#ff8a00;padding:1px 6px;margin:0 2px;cursor:pointer;text-decoration:none}.zm a.on{border-color:#39ff88;color:#39ff88}</style><script>(function(){var z="1";try{z=localStorage.getItem("enduranceZoom")||"1"}catch(e){}function ap(){document.body.style.zoom=z;var a=document.querySelectorAll("#zm a");for(var i=0;i<a.length;i++)a[i].className=a[i].getAttribute("data-z")===z?"on":""}document.getElementById("zm").onclick=function(e){var v=e.target.getAttribute&&e.target.getAttribute("data-z");if(v){z=v;try{localStorage.setItem("enduranceZoom",v)}catch(x){}ap();window.dispatchEvent(new Event("resize"))}};ap()})()</script>'
for _n in ("NETWORK_PAGE", "PAGE", "AUTOSAVE_PAGE", "DEFCON_PAGE", "OSC_PAGE", "DISK_PAGE", "IFACES_PAGE"):
    globals()[_n] = globals()[_n].replace("/*FONT*/", FONT_CSS + FONT_SANS_CSS).replace("</style>", OVER_CSS + "</style>", 1).replace("</body>", ZOOM_UI + "</body>")


# ---- HTTP server: listening only on the chosen ports (and on 127.0.0.1 for the app window) ----
servers = {}                 # indirizzo -> server
serve_lock = threading.Lock()


def bind_wanted():
    sel = netsel_read()
    if sel is None:
        return {"0.0.0.0"}                       # choice never made: as before, on all ports
    w = {"127.0.0.1"}
    for p in list(net_ports):
        if sel.get(p["dev"], False):
            for a in (p.get("ip"), p.get("ll")):
                if a:
                    w.add(a)
    return w


def _close_server(s):
    try:
        s.shutdown()
        s.server_close()
    except Exception:
        pass


def serve_reconcile():
    """Apre i server sulle porte scelte e chiude quelli sulle porte escluse. True se almeno uno e' in ascolto."""
    want = bind_wanted()
    with serve_lock:
        for a in [a for a in servers if a not in want]:
            _close_server(servers.pop(a))      # close first: 0.0.0.0 and a specific address cannot coexist on the same port
        for a in want:
            if a not in servers:
                try:
                    srv = ThreadingHTTPServer((a, HTTP_PORT), Handler)
                except OSError:
                    continue
                servers[a] = srv
                threading.Thread(target=srv.serve_forever, daemon=True).start()
        return bool(servers)


def serve_loop():
    while True:
        time.sleep(3.0)
        try:
            serve_reconcile()
        except Exception as e:
            print("serve:", e)


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"     # reused connections: fewer threads and less work per request
    timeout = 30

    def handle_one_request(self):
        try:
            if local_blocked(self.request.getsockname()[0]):      # request arrived on an excluded port: closed at once
                self.close_connection = True
                return
        except OSError:
            pass
        super().handle_one_request()

    def do_POST(self):
        local = self.client_address[0] in ("127.0.0.1", "::1")
        route, _, query = self.path.partition("?")
        if local and route == "/stop":
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")
            self.wfile.flush()
            threading.Timer(0.3, lambda: os._exit(0)).start()
        elif local and route == "/autosave":
            q = dict(kv.split("=", 1) for kv in query.split("&") if "=" in kv)
            try:
                minutes = min(120.0, max(1.0, float(q.get("minutes", "5"))))
            except ValueError:
                minutes = 5.0
            autosave_set(q.get("enabled") == "1", minutes)
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")
        elif local and route == "/mode":
            q = dict(kv.split("=", 1) for kv in query.split("&") if "=" in kv)
            body = b"ok" if mode_set(q.get("value", "")) else b"error"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif local and route == "/role":
            q = dict(kv.split("=", 1) for kv in query.split("&") if "=" in kv)
            ok = roles_set(q.get("target", ""), q.get("role", ""))
            body = b"ok" if ok else b"error"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif local and route == "/keyapp":
            q = dict(kv.split("=", 1) for kv in query.split("&") if "=" in kv)
            from urllib.parse import unquote_plus as unquote
            body = b"ok" if key_set(unquote(q.get("name", ""))) else b"error"
            kd_wake.set()
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif route in ("/call", "/callin", "/calldismiss", "/keyset") or (local and route in ("/qsync/compare", "/qsync/apply")):
            from urllib.parse import unquote_plus as unquote
            q = dict(kv.split("=", 1) for kv in query.split("&") if "=" in kv)
            ok = False
            extra = b""
            if route == "/callin":
                ok = call_in(self.client_address[0], unquote(q.get("name", "")), q.get("role", ""))
            elif route == "/call":
                ok = call_send(unquote(q.get("ip", "")))
            elif route == "/calldismiss":
                ok = call_dismiss(q.get("id", ""))
            elif route == "/keyset":
                ok = local and kd_set(q.get("k", ""), unquote(q.get("v", "")))
            else:
                r = qs_compare() if route.endswith("compare") else qs_apply()
                ok = bool(r.get("ok"))
                extra = (r.get("err") or "").encode("utf-8", "replace")[:300]
            body = b"ok" if ok else (b"error" + (b":" + extra if extra else b""))
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif route == "/network/discover":
            dev = dict(kv.split("=", 1) for kv in query.split("&") if "=" in kv).get("dev", "")
            ok = bool(re.fullmatch(r"[A-Za-z0-9]{1,12}", dev)) and discover_start(dev)
            body = b"ok" if ok else b"busy"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif route == "/pull":
            q = dict(kv.split("=", 1) for kv in query.split("&") if "=" in kv)
            ok = pull_set_ip(q.get("ip", ""), q.get("on") == "1")
            body = b"ok" if ok else b"error"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif local and route in ("/interfaces/set", "/interfaces/confirm"):
            q = dict(kv.split("=", 1) for kv in query.split("&") if "=" in kv)
            ok = netsel_confirm() if route.endswith("confirm") else netsel_set(q.get("dev", ""), q.get("on") == "1")
            body = b"ok" if ok else b"error"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif route == "/network/clear":
            body = b"ok" if discover_clear() else b"busy"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif route == "/defcon/clear" and not show_mode():
            defcon_clear()
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")
        elif route == "/defcon/sens":
            ok = defcon_set_sens(dict(kv.split("=", 1) for kv in query.split("&") if "=" in kv).get("value", ""))
            body = b"ok" if ok else b"error"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif local and route in ("/osc/enable", "/osc/disable"):
            devs = []
            for kv in query.split("&"):
                if kv.startswith("devs="):
                    devs = [d for d in kv[5:].split(",") if d]
            ok = osc_set(route == "/osc/enable", devs)
            body = b"ok" if ok else b"error"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(403)
            self.send_header("Content-Length", "0")
            self.end_headers()

    def do_GET(self):
        route = self.path.split("?")[0].lower().rstrip("/")
        if route == "/state":
            frm = _clean_name(self.headers.get("X-Endurance-From"))
            if frm and frm != _clean_name(host_name()):
                with pull_lock:
                    watchers[frm] = time.time()
            body = json.dumps(get_state()).encode()
            ctype = "application/json"
        elif route == "/oscdata":
            body = json.dumps(osc_state()).encode()
            ctype = "application/json"
        elif route == "/autosavedata":
            with autosave_lock:
                body = json.dumps({"autosave": dict(autosave), "now": time.time(),
                                   "local": self.client_address[0] in ("127.0.0.1", "::1")}).encode()
            ctype = "application/json"
        elif route == "/defcon":
            body = DEFCON_PAGE.encode()
            ctype = "text/html; charset=utf-8"
        elif route == "/network":
            body = NETWORK_PAGE.encode()
            ctype = "text/html; charset=utf-8"
        elif route == "/networkdata":
            body = json.dumps(network_view(self.client_address[0] in ("127.0.0.1", "::1"))).encode()
            ctype = "application/json"
        elif route == "/ping":
            q = dict(kv.split("=", 1) for kv in self.path.partition("?")[2].split("&") if "=" in kv)
            res = ping_run(q.get("ip", ""))
            body = json.dumps(dict(res or {"ok": False, "error": "address not allowed"}, ip=q.get("ip", ""))).encode()
            ctype = "application/json"
        elif route == "/qsyncdata":
            body = json.dumps(qs_view()).encode()
            ctype = "application/json"
        elif route == "/keyapps":
            body = json.dumps({"apps": list(running_apps), "list": [l for l, _ in KEYAPPS[:1]] + [LPQ] + [l for l, _ in KEYAPPS[1:]], "beta": [l for l, _ in KEYAPPS if l not in KEY_STABLE], "run": {l: any(key_match(n, l) for n in running_apps) for l, _ in KEYAPPS}, "key": LPQ if config.get("lp_extra") else (key_canon(config.get("key_app", "")) or ""), "state": stats.get("key"),
                               "kd": {k: kd_get(k) for k in KD_KEYS}}).encode()
            ctype = "application/json"
        elif route == "/interfaces":
            body = IFACES_PAGE.encode()
            ctype = "text/html; charset=utf-8"
        elif route == "/interfacesdata":
            body = json.dumps(ifaces_view(self.client_address[0] in ("127.0.0.1", "::1"))).encode()
            ctype = "application/json"
        elif route == "/disk":
            body = DISK_PAGE.encode()
            ctype = "text/html; charset=utf-8"
        elif route == "/diskdata":
            body = json.dumps(disk_view()).encode()
            ctype = "application/json"
        elif route == "/defcondata":
            body = json.dumps(defcon_view()).encode()
            ctype = "application/json"
        elif route in ("/defcon/export.pdf", "/defcon/export.csv"):
            pdf = route.endswith("pdf")
            body = defcon_pdf() if pdf else defcon_csv()
            self.send_response(200)
            self.send_header("Content-Type", "application/pdf" if pdf else "text/csv; charset=utf-8")
            self.send_header("Content-Disposition", 'inline; filename="endurance-defcon-log.%s"' % ("pdf" if pdf else "csv"))
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        elif route == "/autosave":
            body = AUTOSAVE_PAGE.encode()
            ctype = "text/html; charset=utf-8"
        elif route == "/osc":
            body = OSC_PAGE.encode()
            ctype = "text/html; charset=utf-8"
        else:
            body = PAGE.encode()
            ctype = "text/html; charset=utf-8"
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


def local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "IP-DEL-MAC"


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--apps":   # open apps using the most RAM (for "Free memory" in the app)
        agg = {}
        for line in run(["ps", "-axo", "rss=,comm="]).splitlines():
            parts = line.split(None, 1)
            if len(parts) == 2 and parts[0].isdigit() and ".app/" in parts[1] and not parts[1].startswith("/System/Library/"):
                k = app_name(parts[1].strip())
                if k != APP_NAME:
                    agg[k] = agg.get(k, 0) + int(parts[0]) / 1048576
        for k, v in sorted(agg.items(), key=lambda kv: kv[1], reverse=True)[:8]:
            if v >= 0.05:
                print("APPS|%s|%.2f|%d" % (k, v, 1 if k.lower().startswith("qlab") else 0))
        sys.exit(0)
    if len(sys.argv) > 1 and sys.argv[1] == "--mem":   # used by the app window for the RAM purge
        mem_report()
        sys.exit(0)
    try:
        os.nice(10)  # low priority: the script always yields to QLab
    except Exception:
        pass
    threading.Thread(target=receiver, daemon=True).start()
    threading.Thread(target=poller, daemon=True).start()
    threading.Thread(target=bk_loop, daemon=True).start()
    threading.Thread(target=kd_loop, daemon=True).start()
    threading.Thread(target=smaart_loop, daemon=True).start()
    threading.Thread(target=sys_stats, daemon=True).start()
    threading.Thread(target=top_apps, daemon=True).start()
    threading.Thread(target=net_loop, daemon=True).start()
    threading.Thread(target=peers_loop, daemon=True).start()
    shutil.rmtree(OSC_DIR, ignore_errors=True)   # OSC monitor always starts off: remove the pipes left over from before
    threading.Thread(target=osc_loop, daemon=True).start()
    _migrate_old_dir()
    autosave_load()
    defcon_load()
    config_load()
    defcon_set_sens("normal" if show_mode() else "strict")
    threading.Thread(target=env_loop, daemon=True).start()
    threading.Thread(target=disk_loop, daemon=True).start()
    threading.Thread(target=defcon_loop, daemon=True).start()
    threading.Thread(target=pull_loop, daemon=True).start()
    threading.Thread(target=autosave_loop, daemon=True).start()
    threading.Thread(target=backup_loop, daemon=True).start()
    print(f"The Endurance {VERSION} - system commands check:")
    for label, fn in (("ram", mem_stats), ("cpu", cpu_percent),
                      ("processi", lambda: len(run(["ps", "-axo", "pid=,time=,rss=,comm="]).splitlines()))):
        try:
            print(f"  {label}: OK {fn()}")
        except Exception as e:
            print(f"  {label}: ERRORE {e}")
    for a in net_addrs() or [{"name": "Rete", "ip": local_ip()}]:
        print(f"Apri sull'iPhone ({a['name']}): http://{a['ip']}:{HTTP_PORT}")
    if not serve_reconcile():
        raise OSError("port %d is not available" % HTTP_PORT)
    threading.Thread(target=serve_loop, daemon=True).start()
    while True:
        time.sleep(3600)
