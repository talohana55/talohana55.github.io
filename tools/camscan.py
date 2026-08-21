#!/usr/bin/env python3
"""
camscan.py - read-only reconnaissance for identifying IP cameras on a LAN.

Pure standard library. Runs on iOS (a-Shell / iSH), macOS and Linux.

READ-ONLY BY DESIGN. It only:
  * opens TCP connections to see which ports answer
  * sends GET / (HTTP), OPTIONS + DESCRIBE (RTSP), and standard read-only
    discovery requests (SSDP M-SEARCH, ONVIF WS-Discovery Probe,
    ONVIF GetSystemDateAndTime / GetDeviceInformation, Xiongmai DVRIP search)
  * listens for broadcasts the devices send out by themselves
It never logs in, never guesses passwords, never POSTs configuration, and
never reboots / resets / updates / re-provisions anything.

Usage:
  python3 camscan.py                      # sweep 192.168.1.0/24, deep-probe what answers
  python3 camscan.py 192.168.1.22 192.168.1.25
  python3 camscan.py --net 192.168.0.0/24
  python3 camscan.py --listen 90          # passive broadcast capture only
  python3 camscan.py --json report.json
"""

import argparse
import errno
import ipaddress
import json
import os
import re
import selectors
import socket
import sys
import time
import uuid

try:
    import ssl
except ImportError:
    ssl = None

TIMEOUT = float(os.environ.get("CAMSCAN_TIMEOUT", "1.6"))
CONC = int(os.environ.get("CAMSCAN_CONC", "96"))

# ports that make a host worth a closer look
SWEEP_PORTS = [80, 81, 443, 554, 8000, 8080, 8081, 8899, 34567, 37777, 6668, 8800, 23, 5000]

DEEP_PORTS = sorted(set(SWEEP_PORTS + [
    21, 22, 25, 82, 88, 2020, 3000, 3702, 4321, 4433, 5001, 5050, 5357, 6666, 6667,
    7000, 7001, 7080, 7443, 8001, 8008, 8010, 8082, 8090, 8100, 8181, 8200, 8443,
    8554, 8600, 8880, 8888, 8889, 8900, 9000, 9001, 9008, 9080, 9090, 9100, 9527,
    9999, 10000, 10001, 11000, 12345, 20000, 23456, 34569, 34599, 49152, 50000,
    55555, 60001,
]))

HTTP_PORTS = {80, 81, 82, 88, 443, 2020, 3000, 4433, 5000, 5001, 7080, 7443, 8000,
              8001, 8008, 8010, 8080, 8081, 8082, 8090, 8100, 8181, 8200, 8443,
              8880, 8888, 8889, 8899, 9000, 9080, 9090, 9999, 10000}
TLS_PORTS = {443, 4433, 7443, 8443}
RTSP_PORTS = {554, 8554, 10554, 555}
ONVIF_PORTS = [80, 8000, 8080, 8899, 2020, 5000, 8081, 81]


# ----------------------------------------------------------------- tcp scan

def tcp_scan(pairs, timeout=TIMEOUT, concurrency=CONC, label=""):
    """Non-blocking TCP connect scan. Returns list of (ip, port) that accepted."""
    pairs = list(pairs)
    total = len(pairs)
    found, done = [], 0
    pending = iter(pairs)
    sel = selectors.DefaultSelector()
    inflight = {}
    exhausted = False
    last_tick = 0.0

    ok_errs = {0, errno.EINPROGRESS, errno.EWOULDBLOCK, errno.EALREADY, errno.EAGAIN}

    while True:
        while not exhausted and len(inflight) < concurrency:
            try:
                ip, port = next(pending)
            except StopIteration:
                exhausted = True
                break
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setblocking(False)
            try:
                err = s.connect_ex((ip, port))
            except OSError:
                s.close(); done += 1; continue
            if err not in ok_errs:
                s.close(); done += 1; continue
            if err == 0:
                found.append((ip, port)); s.close(); done += 1; continue
            try:
                sel.register(s, selectors.EVENT_WRITE)
            except (KeyError, ValueError, OSError):
                s.close(); done += 1; continue
            inflight[s] = (ip, port, time.time() + timeout)

        if not inflight:
            if exhausted:
                break
            continue

        for key, _ in sel.select(0.2):
            s = key.fileobj
            ip, port, _ = inflight.pop(s)
            try:
                sel.unregister(s)
            except (KeyError, ValueError):
                pass
            try:
                e = s.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
            except OSError:
                e = 1
            if e == 0:
                found.append((ip, port))
                print("    open  %s:%d" % (ip, port), flush=True)
            s.close()
            done += 1

        now = time.time()
        for s in [k for k, v in inflight.items() if v[2] <= now]:
            inflight.pop(s)
            try:
                sel.unregister(s)
            except (KeyError, ValueError):
                pass
            s.close()
            done += 1

        if label and now - last_tick > 3:
            last_tick = now
            print("  [%s] %d/%d ... %d open" % (label, done, total, len(found)), flush=True)

    sel.close()
    return sorted(set(found))


# ------------------------------------------------------------ raw exchanges

def tcp_talk(ip, port, payload, timeout=TIMEOUT + 1.5, tls=False, maxbytes=12288):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((ip, port))
        if tls:
            if ssl is None:
                return b""
            ctx = ssl._create_unverified_context()
            ctx.set_ciphers("DEFAULT@SECLEVEL=0")
            s = ctx.wrap_socket(s, server_hostname=ip)
        if payload:
            s.sendall(payload)
        buf = b""
        end = time.time() + timeout
        while len(buf) < maxbytes and time.time() < end:
            try:
                chunk = s.recv(4096)
            except (socket.timeout, OSError):
                break
            if not chunk:
                break
            buf += chunk
        return buf
    except (OSError, ValueError):
        return b""
    finally:
        try:
            s.close()
        except OSError:
            pass


def udp_talk(ip, port, payload, timeout=2.5, expect=1):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    out = []
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    except OSError:
        pass
    try:
        s.sendto(payload, (ip, port))
        end = time.time() + timeout
        while time.time() < end and len(out) < expect:
            try:
                data, src = s.recvfrom(65535)
            except (socket.timeout, OSError):
                break
            if data:
                out.append((src[0], data))
    except OSError:
        pass
    finally:
        s.close()
    return out


# ------------------------------------------------------------------- probes

def http_probe(ip, port, path="/"):
    tls = port in TLS_PORTS
    req = ("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\n"
           "Accept: */*\r\nConnection: close\r\n\r\n" % (path, ip)).encode()
    raw = tcp_talk(ip, port, req, tls=tls)
    if not raw:
        return None
    txt = raw.decode("utf-8", "replace")
    head, _, body = txt.partition("\r\n\r\n")
    info = {"scheme": "https" if tls else "http", "status": head.split("\r\n")[0][:120],
            "headers": {}, "title": None, "body_head": body[:600]}
    for line in head.split("\r\n")[1:]:
        k, _, v = line.partition(":")
        if k:
            info["headers"][k.strip().lower()] = v.strip()[:200]
    m = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
    if m:
        info["title"] = m.group(1).strip()[:120]
    return info


def rtsp_probe(ip, port):
    out = {}
    raw = tcp_talk(ip, port, ("OPTIONS rtsp://%s:%d/ RTSP/1.0\r\nCSeq: 1\r\n"
                              "User-Agent: camscan\r\n\r\n" % (ip, port)).encode())
    if raw:
        out["OPTIONS"] = raw.decode("utf-8", "replace")[:600]
    paths = ["/", "/11", "/live/ch0", "/onvif1", "/stream1", "/h264",
             "/cam/realmonitor?channel=1&subtype=0", "/Streaming/Channels/101",
             "/live/main", "/ch01.264", "/live0.264"]
    for p in paths:
        raw = tcp_talk(ip, port, ("DESCRIBE rtsp://%s:%d%s RTSP/1.0\r\nCSeq: 2\r\n"
                                  "Accept: application/sdp\r\nUser-Agent: camscan\r\n\r\n"
                                  % (ip, port, p)).encode(), timeout=2.0)
        if not raw:
            continue
        txt = raw.decode("utf-8", "replace")
        first = txt.split("\r\n")[0]
        out.setdefault("DESCRIBE", {})[p] = txt[:500]
        if " 200 " in first:
            break
    return out


WSD_PROBE = (
    '<?xml version="1.0" encoding="utf-8"?>'
    '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" '
    'xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing" '
    'xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery" '
    'xmlns:dn="http://www.onvif.org/ver10/network/wsdl">'
    '<s:Header><a:MessageID>uuid:%s</a:MessageID>'
    '<a:To s:mustUnderstand="1">urn:schemas-xmlsoap-org:ws:2005:04:discovery</a:To>'
    '<a:Action s:mustUnderstand="1">http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</a:Action>'
    '</s:Header><s:Body><d:Probe><d:Types>dn:NetworkVideoTransmitter</d:Types></d:Probe>'
    '</s:Body></s:Envelope>'
)

SSDP_MSEARCH = ('M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n'
                'MAN: "ssdp:discover"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n')

# Xiongmai / DVRIP LAN search request (msgid 1530), zero payload. Read-only query.
XM_SEARCH = bytes([0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                   0x00, 0x00, 0x00, 0x00, 0xfa, 0x05, 0x00, 0x00,
                   0x00, 0x00, 0x00, 0x00])

ONVIF_SOAP = (
    '<?xml version="1.0" encoding="utf-8"?>'
    '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">'
    '<s:Body xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
    '<%s xmlns="http://www.onvif.org/ver10/device/wsdl"/>'
    '</s:Body></s:Envelope>'
)


def onvif_probe(ip, port):
    out = {}
    for op in ("GetSystemDateAndTime", "GetDeviceInformation"):
        body = ONVIF_SOAP % op
        req = ("POST /onvif/device_service HTTP/1.1\r\nHost: %s:%d\r\n"
               "Content-Type: application/soap+xml; charset=utf-8\r\n"
               "Content-Length: %d\r\nConnection: close\r\n\r\n%s"
               % (ip, port, len(body), body)).encode()
        raw = tcp_talk(ip, port, req, timeout=3.0)
        if raw:
            txt = raw.decode("utf-8", "replace")
            if "Envelope" in txt or "soap" in txt.lower():
                out[op] = txt[:1500]
    return out


def discovery_unicast(ip):
    out = {}
    r = udp_talk(ip, 1900, SSDP_MSEARCH.encode(), expect=3)
    if r:
        out["ssdp"] = [d.decode("utf-8", "replace")[:900] for _, d in r]
    r = udp_talk(ip, 3702, (WSD_PROBE % uuid.uuid4()).encode(), expect=2)
    if r:
        out["wsdiscovery"] = [d.decode("utf-8", "replace")[:1800] for _, d in r]
    r = udp_talk(ip, 34569, XM_SEARCH, expect=2)
    if r:
        out["xiongmai_dvrip"] = [d.decode("utf-8", "replace")[:900] for _, d in r]
    return out


def discovery_broadcast(bcast="255.255.255.255"):
    """Broadcast + multicast discovery. iOS may block these; unicast is the fallback."""
    out = {}
    for name, ip, port, payload in (
        ("ssdp", "239.255.255.250", 1900, SSDP_MSEARCH.encode()),
        ("ssdp_bcast", bcast, 1900, SSDP_MSEARCH.encode()),
        ("wsdiscovery", "239.255.255.250", 3702, (WSD_PROBE % uuid.uuid4()).encode()),
        ("wsdiscovery_bcast", bcast, 3702, (WSD_PROBE % uuid.uuid4()).encode()),
        ("xiongmai", bcast, 34569, XM_SEARCH),
    ):
        r = udp_talk(ip, port, payload, timeout=3.0, expect=12)
        if r:
            out[name] = [{"from": s, "data": d.decode("utf-8", "replace")[:900]} for s, d in r]
    return out


def fetch_url(url, timeout=4.0):
    m = re.match(r"http://([^/:]+)(?::(\d+))?(/.*)?$", url, re.I)
    if not m:
        return None
    host, port, path = m.group(1), int(m.group(2) or 80), m.group(3) or "/"
    raw = tcp_talk(host, port, ("GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n"
                                % (path, host)).encode(), timeout=timeout)
    return raw.decode("utf-8", "replace") if raw else None


def listen_broadcasts(seconds):
    """Passively receive what devices announce by themselves."""
    ports = [6666, 6667, 6668, 8600, 32108, 34569, 1900, 3702, 5353, 9999, 10000, 8000]
    socks = []
    for p in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        for opt in ("SO_REUSEADDR", "SO_REUSEPORT"):
            try:
                s.setsockopt(socket.SOL_SOCKET, getattr(socket, opt), 1)
            except (AttributeError, OSError):
                pass
        try:
            s.bind(("", p))
            s.setblocking(False)
            socks.append((p, s))
        except OSError:
            s.close()
    if not socks:
        return []
    print("  listening on UDP %s for %ds ..." % (",".join(str(p) for p, _ in socks), seconds),
          flush=True)
    sel = selectors.DefaultSelector()
    for p, s in socks:
        sel.register(s, selectors.EVENT_READ, p)
    seen, end = [], time.time() + seconds
    while time.time() < end:
        for key, _ in sel.select(1.0):
            try:
                data, src = key.fileobj.recvfrom(65535)
            except OSError:
                continue
            rec = {"port": key.data, "from": src[0],
                   "hex": data[:64].hex(),
                   "text": data[:300].decode("utf-8", "replace")}
            seen.append(rec)
            print("    UDP :%d <- %s  %s" % (rec["port"], rec["from"], rec["text"][:80].replace("\n", " ")),
                  flush=True)
    for _, s in socks:
        s.close()
    sel.close()
    return seen


# -------------------------------------------------------------- fingerprint

PORT_SIGNATURES = [
    (34567, "Xiongmai DVRIP (port 34567)", ["XMEye", "iCSee", "iCSee Pro"], 5),
    (8899, "ONVIF on Xiongmai-style firmware (port 8899)", ["iCSee", "XMEye"], 2),
    (37777, "Dahua private protocol (port 37777)", ["DMSS / gDMSS"], 5),
    (8000, "Hikvision/EZVIZ SDK port (port 8000)", ["Hik-Connect", "EZVIZ"], 3),
    (6668, "Tuya local protocol (port 6668)", ["Smart Life", "Tuya Smart"], 5),
    (8800, "V380 / Macrovideo private port (port 8800)", ["V380 Pro"], 4),
    (23, "Telnet open - typical of HiSilicon/Xiongmai busybox firmware", [], 1),
]

TEXT_SIGNATURES = [
    (r"uc-httpd", "uc-httpd webserver = Xiongmai/HiSilicon firmware", ["iCSee", "XMEye", "iCSee Pro"], 5),
    (r"netsurveillance|NetSurveillance", "NetSurveillance web UI = Xiongmai", ["iCSee", "XMEye"], 5),
    (r"[Xx]iongmai|XM\d{3}", "Xiongmai string", ["iCSee", "XMEye"], 5),
    (r"GoAhead-Webs|GoAhead", "GoAhead webserver = HiChip/Wanscam family", ["CamHi", "CamHiPro"], 3),
    (r"[Hh]ichip|HI3518|hipcam|Hipcam", "HiChip / Hi3518 string", ["CamHi", "CamHiPro"], 5),
    (r"[Aa]nyka|AK39\d\d|anjoy", "Anyka chipset string", ["V380 Pro", "iCSee"], 4),
    (r"[Ii]ngenic|T20|T31", "Ingenic chipset string", ["YCC365 Plus", "CloudEdge", "V380 Pro"], 2),
    (r"tuya|Tuya|TUYA", "Tuya string", ["Smart Life", "Tuya Smart"], 5),
    (r"[Dd]ahua|DVRDVS|App-webs", "Dahua string", ["DMSS"], 5),
    (r"[Hh]ikvision|DNVRS-Webs", "Hikvision string", ["Hik-Connect", "EZVIZ"], 5),
    (r"[Ee]zviz", "EZVIZ string", ["EZVIZ"], 5),
    (r"realm=\"?IPCamera", 'HTTP auth realm "IPCamera" = HiChip family', ["CamHi"], 3),
    (r"[Vv]380|[Mm]acrovideo|MV\d{6}", "V380 / Macrovideo string", ["V380 Pro"], 5),
    (r"[Yy][Cc][Cc]365|CloudEdge|cloudedge", "YCC365 / CloudEdge string", ["YCC365 Plus", "CloudEdge"], 5),
    (r"LIVE555", "LIVE555 RTSP server (generic, weak signal)", [], 0),
    (r"Boa/0\.9", "Boa webserver (generic cheap-cam signal)", [], 1),
    (r"JAWS/1\.0", "JAWS webserver = Chinese DVR/NVR firmware", ["XMEye", "iCSee"], 2),
    (r"Rtsp Server|H264DVR", "H264DVR RTSP server = Xiongmai family", ["iCSee", "XMEye"], 3),
    (r"onvif://www\.onvif\.org/(?:name|hardware|manufacturer)/([^ <\"]+)",
     "ONVIF scope reveals name/hardware", [], 6),
    (r"<manufacturer>([^<]+)</manufacturer>", "UPnP manufacturer field", [], 6),
    (r"<modelName>([^<]+)</modelName>", "UPnP model field", [], 6),
    (r"<tds:Manufacturer>([^<]+)", "ONVIF Manufacturer field", [], 8),
    (r"<tds:Model>([^<]+)", "ONVIF Model field", [], 8),
]


def fingerprint(host):
    hits, apps = [], {}
    open_ports = {p for p in host.get("ports", [])}

    for port, why, applist, weight in PORT_SIGNATURES:
        if port in open_ports:
            hits.append({"evidence": why, "weight": weight})
            for a in applist:
                apps[a] = apps.get(a, 0) + weight

    if 554 in open_ports and not (open_ports & {34567, 37777, 6668, 8000, 8800}):
        hits.append({"evidence": "RTSP open but no vendor control port -> cloud-first camera",
                     "weight": 1})

    blob = json.dumps(host.get("services", {}), ensure_ascii=False)
    for pattern, why, applist, weight in TEXT_SIGNATURES:
        m = re.search(pattern, blob)
        if m:
            detail = why
            if m.groups():
                detail = "%s: %s" % (why, m.group(1))
            hits.append({"evidence": detail, "weight": weight})
            for a in applist:
                apps[a] = apps.get(a, 0) + weight

    ranked = sorted(apps.items(), key=lambda kv: -kv[1])
    return {"hits": hits, "app_candidates": ranked}


def is_camera_like(host):
    ports = set(host.get("ports", []))
    if ports & {554, 34567, 37777, 8899, 8800, 6668, 8554}:
        return True
    blob = json.dumps(host.get("services", {}), ensure_ascii=False).lower()
    return any(k in blob for k in ("ipcam", "camera", "onvif", "rtsp", "dvr", "nvr",
                                   "uc-httpd", "goahead", "hichip", "xiongmai"))


# ---------------------------------------------------------------------- run

def deep_probe(ip):
    print("\n[*] deep probe %s" % ip, flush=True)
    host = {"ip": ip, "ports": [], "services": {}}
    host["ports"] = [p for _, p in tcp_scan([(ip, p) for p in DEEP_PORTS], label=ip)]

    for p in host["ports"]:
        if p in HTTP_PORTS:
            r = http_probe(ip, p)
            if r:
                host["services"]["http:%d" % p] = r
                print("    http :%d  %s | server=%s | title=%s" % (
                    p, r["status"], r["headers"].get("server", "-"), r["title"]), flush=True)
                fav = http_probe(ip, p, "/favicon.ico")
                if fav and "200" in fav["status"]:
                    host["services"]["favicon:%d" % p] = fav["status"]
        if p in RTSP_PORTS:
            r = rtsp_probe(ip, p)
            if r:
                host["services"]["rtsp:%d" % p] = r
                first = r.get("OPTIONS", "").split("\r\n")[0]
                print("    rtsp :%d  %s" % (p, first), flush=True)

    for p in ONVIF_PORTS:
        if p in host["ports"]:
            r = onvif_probe(ip, p)
            if r:
                host["services"]["onvif:%d" % p] = r
                print("    onvif :%d responded" % p, flush=True)

    d = discovery_unicast(ip)
    if d:
        host["services"]["discovery"] = d
        print("    discovery: %s" % ", ".join(d.keys()), flush=True)
        for resp in d.get("ssdp", []):
            m = re.search(r"LOCATION:\s*(\S+)", resp, re.I)
            if m:
                doc = fetch_url(m.group(1))
                if doc:
                    host["services"].setdefault("upnp_desc", []).append(doc[:2500])

    host["fingerprint"] = fingerprint(host)
    return host


def main():
    ap = argparse.ArgumentParser(description="read-only IP camera recon")
    ap.add_argument("targets", nargs="*", help="IPs to deep-probe (skips the sweep)")
    ap.add_argument("--net", default="192.168.1.0/24", help="subnet to sweep")
    ap.add_argument("--listen", type=int, default=0, help="passive capture seconds (0=skip)")
    ap.add_argument("--json", default="camscan-report.json")
    ap.add_argument("--no-sweep", action="store_true")
    args = ap.parse_args()

    print("camscan - READ ONLY. no logins, no config writes, no resets.\n")
    report = {"net": args.net, "hosts": [], "broadcast": {}, "passive": []}

    if args.listen:
        print("[*] passive broadcast capture")
        report["passive"] = listen_broadcasts(args.listen)
        if not args.targets:
            save(report, args.json)
            return

    print("[*] broadcast/multicast discovery (iOS may block this - unicast follows)")
    report["broadcast"] = discovery_broadcast()
    for k, v in report["broadcast"].items():
        print("    %s: %d response(s) from %s" % (k, len(v), ", ".join(sorted({x["from"] for x in v}))),
              flush=True)

    targets = list(args.targets)
    if not targets and not args.no_sweep:
        net = ipaddress.ip_network(args.net, strict=False)
        hosts = [str(h) for h in net.hosts()]
        print("\n[*] sweeping %s on %d ports (%d hosts)" % (args.net, len(SWEEP_PORTS), len(hosts)))
        pairs = [(h, p) for p in SWEEP_PORTS for h in hosts]
        hits = tcp_scan(pairs, label="sweep")
        targets = sorted({ip for ip, _ in hits}, key=lambda x: tuple(int(o) for o in x.split(".")))
        print("\n[*] %d hosts answered: %s" % (len(targets), ", ".join(targets)))

    for ip in targets:
        try:
            report["hosts"].append(deep_probe(ip))
        except KeyboardInterrupt:
            raise
        except Exception as e:
            report["hosts"].append({"ip": ip, "error": repr(e)})

    summarize(report)
    save(report, args.json)


def summarize(report):
    print("\n" + "=" * 62)
    print("SUMMARY  (paste this part back)")
    print("=" * 62)
    for h in report["hosts"]:
        if "error" in h:
            print("\n%-15s ERROR %s" % (h["ip"], h["error"]))
            continue
        cam = "  <-- CAMERA-LIKE" if is_camera_like(h) else ""
        print("\n%-15s ports: %s%s" % (h["ip"],
              ",".join(str(p) for p in h["ports"]) or "none", cam))
        for k, v in sorted(h.get("services", {}).items()):
            if k.startswith("http:"):
                print("    %-12s %s | server=%s | realm=%s | title=%s" % (
                    k, v["status"], v["headers"].get("server", "-"),
                    v["headers"].get("www-authenticate", "-")[:60], v["title"]))
            elif k.startswith("rtsp:"):
                print("    %-12s %s" % (k, v.get("OPTIONS", "").split("\r\n")[0]))
                for hdr in ("Server", "WWW-Authenticate", "Public"):
                    m = re.search(r"^%s:\s*(.+)$" % hdr, v.get("OPTIONS", ""), re.I | re.M)
                    if m:
                        print("                 %s: %s" % (hdr, m.group(1).strip()[:90]))
                for path, resp in (v.get("DESCRIBE") or {}).items():
                    line = resp.split("\r\n")[0]
                    if "200" in line or "401" in line:
                        print("                 DESCRIBE %s -> %s" % (path, line))
        fp = h.get("fingerprint", {})
        for hit in fp.get("hits", []):
            print("    [+] %s" % hit["evidence"])
        if fp.get("app_candidates"):
            print("    => likely app: %s" % ", ".join(
                "%s(%d)" % (a, s) for a, s in fp["app_candidates"][:4]))
    print("\n" + "=" * 62)


def save(report, path):
    try:
        with open(path, "w") as f:
            json.dump(report, f, indent=1, ensure_ascii=False)
        print("full evidence written to %s" % path)
    except OSError as e:
        print("could not write %s: %s" % (path, e))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\ninterrupted")
