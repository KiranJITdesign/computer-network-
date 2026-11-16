#!/usr/bin/env python3
"""
NetPulse — Live 3D Network Traffic Animator Backend
Run:
    sudo python server.py              # Live NIC packet capture + GeoIP + WebSocket stream
    sudo python server.py --gestures   # Also enable OpenCV + MediaPipe hand-gesture globe control
"""
import asyncio
from contextlib import asynccontextmanager
import json
import os
import sys
import threading
import time
from typing import Dict, Optional, Set

import httpx
import uvicorn
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from scapy.all import ARP, DNS, Ether, IP, TCP, UDP, sniff, srp, wrpcap


@asynccontextmanager
async def lifespan(app_instance: FastAPI):
    loop = asyncio.get_running_loop()
    threading.Thread(target=start_scapy_sniffer, args=(loop,), daemon=True).start()
    broadcaster_task = asyncio.create_task(broadcast_packet_worker())
    arp_task = asyncio.create_task(periodic_arp_scanner())
    if "--gestures" in sys.argv:
        threading.Thread(target=start_mediapipe_gesture_worker, args=(loop,), daemon=True).start()
    yield
    broadcaster_task.cancel()
    arp_task.cancel()


app = FastAPI(title="NetPulse Live 3D Network Telemetry Backend", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

CACHE_FILE = "geoip_cache.json"
PCAP_FILE = "session_capture.pcap"
SUSPICIOUS_PORTS = {21, 22, 23, 25, 135, 139, 445, 1433, 3389, 4444, 5900, 6667, 8081, 31337}
SUSPICIOUS_PREFIXES = ("185.220.", "45.155.205.", "194.26.135.", "91.240.118.", "89.248.165.")

clients: Set[WebSocket] = set()
packet_queue: asyncio.Queue = asyncio.Queue(maxsize=600)
captured_packets = []
geo_cache: Dict[str, dict] = {}

if os.path.exists(CACHE_FILE):
    try:
        with open(CACHE_FILE, "r", encoding="utf-8") as f:
            geo_cache = json.load(f)
    except Exception:
        geo_cache = {}


def save_geo_cache() -> None:
    try:
        with open(CACHE_FILE, "w", encoding="utf-8") as f:
            json.dump(geo_cache, f, indent=2)
    except Exception:
        pass


def is_private_or_multicast_ip(ip: str) -> bool:
    if (
        ip.startswith("10.")
        or ip.startswith("192.168.")
        or ip.startswith("127.")
        or ip.startswith("169.254.")
        or ip.startswith("224.")
        or ip.startswith("239.")
        or ip == "255.255.255.255"
    ):
        return True
    if ip.startswith("172."):
        parts = ip.split(".")
        if len(parts) > 1 and parts[1].isdigit() and 16 <= int(parts[1]) <= 31:
            return True
    return False


async def resolve_geoip(ip: str) -> Optional[dict]:
    if ip in geo_cache:
        return geo_cache[ip]
    try:
        async with httpx.AsyncClient(timeout=3.5) as client:
            url = f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,lat,lon,isp"
            resp = await client.get(url)
            data = resp.json()
            if data.get("status") == "success":
                entry = {
                    "ip": ip,
                    "city": data.get("city") or "Global Edge",
                    "country": data.get("country") or "Internet",
                    "countryCode": data.get("countryCode") or "GL",
                    "lat": float(data["lat"]),
                    "lon": float(data["lon"]),
                    "isp": data.get("isp") or "External ASN",
                }
                geo_cache[ip] = entry
                save_geo_cache()
                return entry
    except Exception:
        pass
    return None


def start_scapy_sniffer(loop: asyncio.AbstractEventLoop) -> None:
    def handle_packet(pkt) -> None:
        if not pkt.haslayer(IP):
            return
        captured_packets.append(pkt)
        if len(captured_packets) % 100 == 0:
            try:
                wrpcap(PCAP_FILE, captured_packets[-2000:])
            except Exception:
                pass
        ip_layer = pkt[IP]
        src_ip, dst_ip = ip_layer.src, ip_layer.dst
        remote_ip = dst_ip if not is_private_or_multicast_ip(dst_ip) else (src_ip if not is_private_or_multicast_ip(src_ip) else None)
        if not remote_ip:
            return
        proto, dst_port = "OTHER", 0
        if pkt.haslayer(DNS):
            proto, dst_port = "DNS", 53
        elif pkt.haslayer(TCP):
            sport, dport = int(pkt[TCP].sport), int(pkt[TCP].dport)
            dst_port = dport if not is_private_or_multicast_ip(dst_ip) else sport
            proto = "HTTPS" if (sport in (443, 8443) or dport in (443, 8443)) else "OTHER"
        elif pkt.haslayer(UDP):
            sport, dport = int(pkt[UDP].sport), int(pkt[UDP].dport)
            dst_port = dport if not is_private_or_multicast_ip(dst_ip) else sport
            proto = "DNS" if (sport == 53 or dport == 53) else "OTHER"
        is_suspicious = (dst_port in SUSPICIOUS_PORTS) or remote_ip.startswith(SUSPICIOUS_PREFIXES)
        event = {
            "ts": int(time.time() * 1000),
            "src_ip": src_ip,
            "dst_ip": remote_ip,
            "protocol": proto,
            "dst_port": dst_port,
            "size": len(pkt),
            "suspicious": is_suspicious,
        }
        try:
            loop.call_soon_threadsafe(packet_queue.put_nowait, event)
        except asyncio.QueueFull:
            pass

    print("[*] Capturing live packets via Scapy (press Ctrl+C to stop)...")
    try:
        sniff(prn=handle_packet, store=False)
    except Exception as exc:
        print(f"[!] Packet capture error: {exc}")


async def broadcast_packet_worker() -> None:
    while True:
        event = await packet_queue.get()
        geo = await resolve_geoip(event["dst_ip"])
        if not geo:
            continue
        event["geo"] = geo
        event["host"] = geo["isp"]
        payload = json.dumps(event)
        for ws in list(clients):
            try:
                await ws.send_text(payload)
            except Exception:
                clients.discard(ws)


async def periodic_arp_scanner() -> None:
    while True:
        try:
            ans, _ = await asyncio.to_thread(srp, Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst="192.168.1.0/24"), timeout=2, verbose=False)
            devices = [{"ip": rcv.psrc, "mac": rcv.hwsrc, "vendor": "LAN ARP Endpoint"} for _, rcv in ans]
            if devices and clients:
                msg = json.dumps({"type": "lan_scan", "devices": devices})
                for ws in list(clients):
                    try:
                        await ws.send_text(msg)
                    except Exception:
                        clients.discard(ws)
        except Exception:
            pass
        await asyncio.sleep(20)


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket) -> None:
    await websocket.accept()
    clients.add(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        clients.discard(websocket)


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
