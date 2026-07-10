"""
live_capture.py
---------------
Captures live packets from a network interface, groups them into flows,
computes CICFlowMeter-compatible features, and feeds them into your
existing RF / XGB / ISO models.

Architecture:
    NIC → pyshark capture → FlowTracker → feature vector (40 cols)
        → preprocess.py → predictor.py → live state → /api/live

Requirements:
    pip install pyshark numpy pandas

    Linux:   sudo apt install tshark   (then add yourself to wireshark group)
    macOS:   brew install wireshark
    Windows: install Wireshark, run as Admin

Usage (standalone test):
    sudo python3 live_capture.py --iface eth0 --duration 60

Integration with Flask (in app.py):
    from src.models.live_capture import LiveCaptureEngine
    engine = LiveCaptureEngine(models)
    engine.start("eth0")   # POST /api/live/start
    engine.stop()          # POST /api/live/stop
"""

import time
import threading
import math
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional
from datetime import datetime, timezone
import numpy as np
import pandas as pd

# ── Severity & SOC-style incident classification ───────────────────────────────

CRITICAL_TYPES = {"DDoS", "DoS Hulk", "DoS GoldenEye", "DoS slowloris", "DoS Slowhttptest", "Heartbleed"}
HIGH_TYPES     = {"PortScan", "FTP-Patator", "SSH-Patator", "Bot"}

RECOMMENDED_ACTIONS = {
    "DDoS":              "Rate-limit or null-route source IP(s); engage upstream DDoS mitigation.",
    "DoS Hulk":          "Block source IP at firewall; investigate target service load.",
    "DoS GoldenEye":     "Block source IP at firewall; investigate target service load.",
    "DoS slowloris":     "Block source IP; tune server connection/timeout limits.",
    "DoS Slowhttptest":  "Block source IP; tune server connection/timeout limits.",
    "Heartbleed":        "Isolate affected host immediately; patch OpenSSL; rotate certs/keys.",
    "PortScan":          "Block source IP at perimeter firewall; review exposed ports.",
    "FTP-Patator":       "Block source IP; enforce account lockout / MFA on FTP service.",
    "SSH-Patator":       "Block source IP; enforce account lockout / MFA on SSH service.",
    "Bot":               "Isolate host, scan for malware, block C2 destination if known.",
    "Anomaly":           "Investigate flow manually — flagged by anomaly detector only.",
}
DEFAULT_ACTION = "Investigate flow manually and validate against known traffic baselines."


def classify_severity(label: str, iso_score: float, confidence: float) -> str:
    """Maps a prediction to a SOC-style severity tier."""
    if label in CRITICAL_TYPES:
        return "Critical"
    if label not in ("BENIGN", "Anomaly"):
        if label in HIGH_TYPES:
            return "High" if confidence >= 70 else "Medium"
        return "High"
    if label == "Anomaly" or iso_score < -0.5:
        return "Medium" if confidence >= 60 else "Low"
    return "Low"


def recommended_action(label: str) -> str:
    return RECOMMENDED_ACTIONS.get(label, DEFAULT_ACTION)


# ── Flow key ─────────────────────────────────────────────────────────────────

def _flow_key(src_ip, dst_ip, src_port, dst_port, protocol):
    """Bidirectional flow key — same key regardless of who sent first."""
    fwd = (src_ip, dst_ip, src_port, dst_port, protocol)
    bwd = (dst_ip, src_ip, dst_port, src_port, protocol)
    return min(fwd, bwd)   # consistent ordering


# ── Per-packet record ─────────────────────────────────────────────────────────

@dataclass
class PacketRecord:
    timestamp:   float
    length:      int
    direction:   int      # 0 = forward (first seen), 1 = backward
    tcp_flags:   int      # bitmask: FIN=1 SYN=2 RST=4 PSH=8 ACK=16 URG=32
    win_size:    int
    header_len:  int
    payload_len: int


# ── Flow accumulator ─────────────────────────────────────────────────────────

@dataclass
class Flow:
    key:          tuple
    protocol:     int       # 6=TCP, 17=UDP
    start_time:   float
    last_time:    float
    packets:      list      = field(default_factory=list)

    # The actual 5-tuple of whoever sent the FIRST packet in this flow.
    # "Forward" = this side, regardless of how IPs/ports sort lexicographically.
    fwd_tuple:    tuple = None
    dst_port:     int   = 0   # destination port of the flow initiator (real CICFlowMeter "Destination Port")

    # Init window bytes (from first SYN packet)
    init_win_fwd: int = 0
    init_win_bwd: int = 0
    fwd_init_set: bool = False
    bwd_init_set: bool = False

    # Active/idle time tracking
    _last_active: float = 0.0
    active_times: list  = field(default_factory=list)
    idle_times:   list  = field(default_factory=list)
    ACTIVE_TIMEOUT: float = 1.0   # seconds — gap > this = idle

    def add_packet(self, pkt: PacketRecord):
        # Active / idle segmentation
        if self.packets:
            gap = pkt.timestamp - self.last_time
            if gap > self.ACTIVE_TIMEOUT:
                self.idle_times.append(gap)
            else:
                if self._last_active == 0:
                    self._last_active = self.last_time
                self.active_times.append(gap)
        else:
            self._last_active = pkt.timestamp

        self.packets.append(pkt)
        self.last_time = pkt.timestamp

        # Capture init window sizes
        if pkt.direction == 0 and not self.fwd_init_set:
            self.init_win_fwd = pkt.win_size
            self.fwd_init_set = True
        if pkt.direction == 1 and not self.bwd_init_set:
            self.init_win_bwd = pkt.win_size
            self.bwd_init_set = True

    def is_finished(self, now: float, idle_timeout: float = 120.0) -> bool:
        """Flow ends on TCP FIN/RST or long idle."""
        if now - self.last_time > idle_timeout:
            return True
        for p in self.packets[-3:]:   # check last few packets
            if p.tcp_flags & 0x01 or p.tcp_flags & 0x04:  # FIN or RST
                return True
        return False


# ── Feature computation ───────────────────────────────────────────────────────

def _safe_stats(values):
    """Returns (mean, std, max, min) safely for an empty list."""
    if not values:
        return 0.0, 0.0, 0.0, 0.0
    a = np.array(values, dtype=float)
    return float(a.mean()), float(a.std()), float(a.max()), float(a.min())


def _safe_div(a, b):
    return a / b if b else 0.0


def compute_features(flow: Flow) -> Optional[dict]:
    """
    Compute CICFlowMeter-compatible features from a finished flow.
    Returns a dict with exactly the column names CICFlowMeter produces.
    Returns None if the flow has fewer than 2 packets (can't compute stats).
    """
    pkts = flow.packets
    if len(pkts) < 2:
        return None

    duration = max(flow.last_time - flow.start_time, 1e-6)  # seconds

    fwd = [p for p in pkts if p.direction == 0]
    bwd = [p for p in pkts if p.direction == 1]

    fwd_lens    = [p.length      for p in fwd]
    bwd_lens    = [p.length      for p in bwd]
    fwd_payload = [p.payload_len for p in fwd]
    bwd_payload = [p.payload_len for p in bwd]

    # Inter-arrival times
    all_ts  = [p.timestamp for p in pkts]
    fwd_ts  = [p.timestamp for p in fwd]
    bwd_ts  = [p.timestamp for p in bwd]

    flow_iats = [all_ts[i+1] - all_ts[i]     for i in range(len(all_ts)-1)]
    fwd_iats  = [fwd_ts[i+1] - fwd_ts[i]     for i in range(len(fwd_ts)-1)]
    bwd_iats  = [bwd_ts[i+1] - bwd_ts[i]     for i in range(len(bwd_ts)-1)]

    # Packet length stats
    all_lens = fwd_lens + bwd_lens
    pl_mean, pl_std, pl_max, pl_min = _safe_stats(all_lens)
    fpl_mean, fpl_std, fpl_max, fpl_min = _safe_stats(fwd_lens)
    bpl_mean, bpl_std, bpl_max, bpl_min = _safe_stats(bwd_lens)

    # IAT stats
    fi_mean, fi_std, fi_max, fi_min = _safe_stats(flow_iats)
    fwd_iat_mean, fwd_iat_std, fwd_iat_max, fwd_iat_min = _safe_stats(fwd_iats)
    bwd_iat_mean, bwd_iat_std, bwd_iat_max, bwd_iat_min = _safe_stats(bwd_iats)

    # Active / idle
    act_mean, act_std, act_max, act_min = _safe_stats(flow.active_times)
    idl_mean, idl_std, idl_max, idl_min = _safe_stats(flow.idle_times)

    # Flag counts
    def flag_count(pkt_list, mask):
        return sum(1 for p in pkt_list if p.tcp_flags & mask)

    total_pkts = len(pkts)
    fwd_pkts   = len(fwd)
    bwd_pkts   = len(bwd)

    total_bytes     = sum(all_lens)
    fwd_bytes       = sum(fwd_lens)
    bwd_bytes       = sum(bwd_lens)
    fwd_header_len  = sum(p.header_len for p in fwd)
    bwd_header_len  = sum(p.header_len for p in bwd)

    bytes_per_sec   = _safe_div(total_bytes, duration)
    pkts_per_sec    = _safe_div(total_pkts,  duration)
    fwd_pkts_per_s  = _safe_div(fwd_pkts,   duration)
    bwd_pkts_per_s  = _safe_div(bwd_pkts,   duration)

    # Subflow approximation (simple: treat whole flow as one subflow)
    subflow_fwd_pkts  = fwd_pkts
    subflow_bwd_pkts  = bwd_pkts
    subflow_fwd_bytes = fwd_bytes
    subflow_bwd_bytes = bwd_bytes

    # Avg packet size
    avg_pkt_size = _safe_div(total_bytes, total_pkts)
    avg_fwd_seg  = _safe_div(fwd_bytes,   fwd_pkts)
    avg_bwd_seg  = _safe_div(bwd_bytes,   bwd_pkts)

    # Down/up ratio
    down_up_ratio = _safe_div(bwd_bytes, fwd_bytes)

    # PSH / URG flags
    fwd_psh = flag_count(fwd, 0x08)
    bwd_psh = flag_count(bwd, 0x08)
    fwd_urg = flag_count(fwd, 0x20)
    bwd_urg = flag_count(bwd, 0x20)

    # SYN / FIN / RST / ACK counts across all packets
    syn_cnt = flag_count(pkts, 0x02)
    fin_cnt = flag_count(pkts, 0x01)
    rst_cnt = flag_count(pkts, 0x04)
    ack_cnt = flag_count(pkts, 0x10)

    # CWE flag (ECN-aware; bit 7 in TCP flags — unusual, set to 0 if absent)
    cwe_cnt = flag_count(pkts, 0x80)

    # Fwd bulk — placeholder (requires complex stateful tracking; set 0)
    fwd_avg_bulk_rate = 0.0
    bwd_avg_bulk_rate = 0.0
    fwd_avg_bytes_bulk = 0.0
    bwd_avg_bytes_bulk = 0.0
    fwd_avg_pkts_bulk  = 0.0
    bwd_avg_pkts_bulk  = 0.0

    # ── Build the dict with CICFlowMeter column names ─────────────────────────
    # Column names must match exactly what your selected_features.pkl contains.
    # These are the standard CICFlowMeter output column names (stripped).
    features = {
        "Destination Port":              flow.dst_port,
        "Protocol":                      flow.protocol,
        "Flow Duration":                 int(duration * 1e6),  # microseconds
        "Total Fwd Packets":             fwd_pkts,
        "Total Backward Packets":        bwd_pkts,
        "Total Length of Fwd Packets":   fwd_bytes,
        "Total Length of Bwd Packets":   bwd_bytes,
        "Fwd Packet Length Max":         fpl_max,
        "Fwd Packet Length Min":         fpl_min,
        "Fwd Packet Length Mean":        fpl_mean,
        "Fwd Packet Length Std":         fpl_std,
        "Bwd Packet Length Max":         bpl_max,
        "Bwd Packet Length Min":         bpl_min,
        "Bwd Packet Length Mean":        bpl_mean,
        "Bwd Packet Length Std":         bpl_std,
        "Flow Bytes/s":                  bytes_per_sec,
        "Flow Packets/s":                pkts_per_sec,
        "Flow IAT Mean":                 fi_mean,
        "Flow IAT Std":                  fi_std,
        "Flow IAT Max":                  fi_max,
        "Flow IAT Min":                  fi_min,
        "Fwd IAT Total":                 sum(fwd_iats),
        "Fwd IAT Mean":                  fwd_iat_mean,
        "Fwd IAT Std":                   fwd_iat_std,
        "Fwd IAT Max":                   fwd_iat_max,
        "Fwd IAT Min":                   fwd_iat_min,
        "Bwd IAT Total":                 sum(bwd_iats),
        "Bwd IAT Mean":                  bwd_iat_mean,
        "Bwd IAT Std":                   bwd_iat_std,
        "Bwd IAT Max":                   bwd_iat_max,
        "Bwd IAT Min":                   bwd_iat_min,
        "Fwd PSH Flags":                 fwd_psh,
        "Bwd PSH Flags":                 bwd_psh,
        "Fwd URG Flags":                 fwd_urg,
        "Bwd URG Flags":                 bwd_urg,
        "Fwd Header Length":             fwd_header_len,
        "Bwd Header Length":             bwd_header_len,
        "Fwd Packets/s":                 fwd_pkts_per_s,
        "Bwd Packets/s":                 bwd_pkts_per_s,
        "Min Packet Length":             pl_min,
        "Max Packet Length":             pl_max,
        "Packet Length Mean":            pl_mean,
        "Packet Length Std":             pl_std,
        "Packet Length Variance":        pl_std ** 2,
        "FIN Flag Count":                fin_cnt,
        "SYN Flag Count":                syn_cnt,
        "RST Flag Count":                rst_cnt,
        "PSH Flag Count":                flag_count(pkts, 0x08),
        "ACK Flag Count":                ack_cnt,
        "URG Flag Count":                flag_count(pkts, 0x20),
        "CWE Flag Count":                cwe_cnt,
        "ECE Flag Count":                flag_count(pkts, 0x40),
        "Down/Up Ratio":                 down_up_ratio,
        "Average Packet Size":           avg_pkt_size,
        "Avg Fwd Segment Size":          avg_fwd_seg,
        "Avg Bwd Segment Size":          avg_bwd_seg,
        "Fwd Header Length.1":           fwd_header_len,   # CICFlowMeter duplicate
        "Fwd Avg Bytes/Bulk":            fwd_avg_bytes_bulk,
        "Fwd Avg Packets/Bulk":          fwd_avg_pkts_bulk,
        "Fwd Avg Bulk Rate":             fwd_avg_bulk_rate,
        "Bwd Avg Bytes/Bulk":            bwd_avg_bytes_bulk,
        "Bwd Avg Packets/Bulk":          bwd_avg_pkts_bulk,
        "Bwd Avg Bulk Rate":             bwd_avg_bulk_rate,
        "Subflow Fwd Packets":           subflow_fwd_pkts,
        "Subflow Fwd Bytes":             subflow_fwd_bytes,
        "Subflow Bwd Packets":           subflow_bwd_pkts,
        "Subflow Bwd Bytes":             subflow_bwd_bytes,
        "Init_Win_bytes_forward":        flow.init_win_fwd,
        "Init_Win_bytes_backward":       flow.init_win_bwd,
        "act_data_pkt_fwd":              sum(1 for p in fwd if p.payload_len > 0),
        "min_seg_size_forward":          min((p.header_len for p in fwd), default=0),
        "Active Mean":                   act_mean,
        "Active Std":                    act_std,
        "Active Max":                    act_max,
        "Active Min":                    act_min,
        "Idle Mean":                     idl_mean,
        "Idle Std":                      idl_std,
        "Idle Max":                      idl_max,
        "Idle Min":                      idl_min,
    }

    # Replace NaN / Inf with 0 (same as your preprocess.py)
    for k, v in features.items():
        if isinstance(v, float) and (math.isnan(v) or math.isinf(v)):
            features[k] = 0.0

    return features


# ── Flow tracker ──────────────────────────────────────────────────────────────

class FlowTracker:
    """
    Maintains a dict of active flows keyed by 5-tuple.
    Call `add_packet()` for each captured packet.
    Call `expire_flows()` periodically to get finished flows.
    """

    IDLE_TIMEOUT = 120.0   # seconds — CICFlowMeter default

    def __init__(self):
        self._flows: dict[tuple, Flow] = {}
        self._lock = threading.Lock()

    def add_packet(self, src_ip, dst_ip, src_port, dst_port,
                   protocol, timestamp, length, tcp_flags=0,
                   win_size=0, header_len=20, payload_len=0):

        key = _flow_key(src_ip, dst_ip, src_port, dst_port, protocol)
        this_tuple = (src_ip, dst_ip, src_port, dst_port, protocol)

        with self._lock:
            if key not in self._flows:
                flow = Flow(
                    key=key,
                    protocol=protocol,
                    start_time=timestamp,
                    last_time=timestamp,
                )
                # "Forward" = whoever sent the FIRST packet of this flow
                # (true CICFlowMeter convention), not lexicographic sort.
                flow.fwd_tuple = this_tuple
                flow.dst_port  = dst_port
                self._flows[key] = flow
            else:
                flow = self._flows[key]

            direction = 0 if this_tuple == flow.fwd_tuple else 1

            pkt = PacketRecord(
                timestamp=timestamp,
                length=length,
                direction=direction,
                tcp_flags=tcp_flags,
                win_size=win_size,
                header_len=header_len,
                payload_len=payload_len,
            )
            flow.add_packet(pkt)

    def expire_flows(self, now: float) -> list[dict]:
        """
        Check all active flows. Return finished flows as
        [{"meta": {...identifying fields...}, "features": {...model columns...}}, ...]
        Call this every second or so from your background thread.
        """
        finished = []
        with self._lock:
            finished_keys = [
                k for k, f in self._flows.items()
                if f.is_finished(now, self.IDLE_TIMEOUT)
            ]
            for k in finished_keys:
                flow = self._flows.pop(k)
                feats = compute_features(flow)
                if feats is not None:
                    meta = {
                        "src_ip":   flow.fwd_tuple[0] if flow.fwd_tuple else None,
                        "dst_ip":   flow.fwd_tuple[1] if flow.fwd_tuple else None,
                        "src_port": flow.fwd_tuple[2] if flow.fwd_tuple else None,
                        "dst_port": flow.dst_port,
                        "protocol": flow.protocol,
                    }
                    finished.append({"meta": meta, "features": feats})

        return finished


# ── Live capture engine ───────────────────────────────────────────────────────

class LiveCaptureEngine:
    """
    Wraps pyshark capture + FlowTracker + your existing models.

    Usage:
        engine = LiveCaptureEngine(models)
        engine.start("eth0")
        # ... later ...
        engine.stop()
        stats = engine.get_stats()
    """

    def __init__(self, models: dict):
        self.models   = models
        self._tracker = FlowTracker()
        self._running = False
        self._thread  = None
        self._expire_thread = None
        self._lock    = threading.Lock()

        # Cumulative live stats
        self._live = self._empty_live()

        # Uncapped session record — for "Export Live Alerts" / "Export Live Session"
        self._session_alerts     = []
        self._session_interface  = None
        self._session_started_at = None

    def _empty_live(self):
        return {
            "total_flows":    0,
            "benign_count":   0,
            "threat_count":   0,
            "rf_threats":     0,
            "xgb_threats":    0,
            "iso_anomalies":  0,
            "label_counts":   {},
            "latest_alerts":  [],
            "timeline":       [],
            "detection_rate": 0.0,
        }

    # ── Public API ────────────────────────────────────────────────────────────

    def start(self, interface: str):
        """Start capturing on `interface` (e.g. 'eth0', 'en0', 'Wi-Fi')."""
        if self._running:
            return
        self._running = True
        self._live    = self._empty_live()
        self._tracker = FlowTracker()

        self._session_alerts     = []
        self._session_interface  = interface
        self._session_started_at = datetime.now(timezone.utc).isoformat()

        self._thread = threading.Thread(
            target=self._capture_loop,
            args=(interface,),
            daemon=True,
        )
        self._expire_thread = threading.Thread(
            target=self._expire_loop,
            daemon=True,
        )
        self._thread.start()
        self._expire_thread.start()

    def stop(self):
        self._running = False

    def get_stats(self) -> dict:
        with self._lock:
            return dict(self._live)

    def get_session_export(self) -> dict:
        """Full session record for the 'Export Live Session' button."""
        with self._lock:
            return {
                "interface":   self._session_interface,
                "started_at":  self._session_started_at,
                "exported_at": datetime.now(timezone.utc).isoformat(),
                "running":     self._running,
                "summary":     {k: v for k, v in self._live.items() if k != "latest_alerts"},
                "incidents":   list(self._session_alerts),   # uncapped, newest-first
            }

    # ── Capture loop ──────────────────────────────────────────────────────────

    def _capture_loop(self, interface: str):
        try:
            import pyshark
        except ImportError:
            raise RuntimeError("pyshark not installed — run: pip install pyshark")

        # Python 3.10+ removed implicit event loop creation in background threads.
        # pyshark calls get_event_loop() internally, so we must create one first.
        import asyncio
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        capture = pyshark.LiveCapture(
            interface=interface,
            display_filter="ip and (tcp or udp)",
        )

        for pkt in capture.sniff_continuously():
            if not self._running:
                capture.close()
                break
            try:
                self._process_packet(pkt)
            except Exception:
                pass   # malformed packet — skip

    def _process_packet(self, pkt):
        """Extract fields from a pyshark packet and hand to FlowTracker."""
        ts = float(pkt.sniff_timestamp)

        # IP layer
        src_ip = str(pkt.ip.src)
        dst_ip = str(pkt.ip.dst)

        # Transport layer
        if hasattr(pkt, "tcp"):
            proto     = 6
            src_port  = int(pkt.tcp.srcport)
            dst_port  = int(pkt.tcp.dstport)
            tcp_flags = int(pkt.tcp.flags, 16)
            win_size  = int(pkt.tcp.window_size)
            hdr_len   = int(pkt.tcp.hdr_len)
        elif hasattr(pkt, "udp"):
            proto     = 17
            src_port  = int(pkt.udp.srcport)
            dst_port  = int(pkt.udp.dstport)
            tcp_flags = 0
            win_size  = 0
            hdr_len   = 8
        else:
            return

        # Use the IP layer's own length field, not pyshark's frame length
        # (which includes the Ethernet header/trailer). CICFlowMeter measures
        # from the IP layer, so using frame length would inflate every
        # length-derived feature by a constant ~14 bytes per packet.
        try:
            pkt_len = int(pkt.ip.len)
        except (AttributeError, ValueError):
            pkt_len = max(0, int(pkt.length) - 14)  # fallback: strip Ethernet header estimate
        payload_len = max(0, pkt_len - hdr_len - 20)  # approx (IP hdr=20)

        self._tracker.add_packet(
            src_ip=src_ip, dst_ip=dst_ip,
            src_port=src_port, dst_port=dst_port,
            protocol=proto,
            timestamp=ts,
            length=pkt_len,
            tcp_flags=tcp_flags,
            win_size=win_size,
            header_len=hdr_len,
            payload_len=payload_len,
        )

    # ── Expire loop ───────────────────────────────────────────────────────────

    def _expire_loop(self):
        """Every second, expire finished flows and run predictions."""
        from src.models.preprocess import prepare_inputs
        from src.models.predictor  import predict_rf, predict_xgb, predict_iso

        while self._running:
            time.sleep(1.0)
            now      = time.time()
            finished = self._tracker.expire_flows(now)

            if not finished:
                continue

            meta_list     = [f["meta"]     for f in finished]
            feature_dicts = [f["features"] for f in finished]

            try:
                df       = pd.DataFrame(feature_dicts)
                X_raw, X_iso = prepare_inputs(df, self.models)

                rf_labels,  rf_probas  = predict_rf(X_raw,  self.models)
                xgb_labels, xgb_probas = predict_xgb(X_raw, self.models)
                iso_scores             = predict_iso(X_iso,  self.models)
            except Exception as e:
                print(f"[live_capture] Prediction error: {e}")
                continue

            ts_now      = datetime.now(timezone.utc).isoformat()
            new_threats = 0
            PROTO_NAME  = {6: "TCP", 17: "UDP"}

            with self._lock:
                for i in range(len(rf_labels)):
                    rf   = rf_labels[i]
                    xgb  = xgb_labels[i]
                    iso  = iso_scores[i]
                    meta = meta_list[i]

                    self._live["total_flows"] += 1

                    is_threat = (rf != "BENIGN") or (xgb != "BENIGN") or (iso < -0.5)

                    if is_threat:
                        self._live["threat_count"] += 1
                        new_threats += 1
                        label = rf if rf != "BENIGN" else (xgb if xgb != "BENIGN" else "Anomaly")
                        lc = self._live["label_counts"]
                        lc[label] = lc.get(label, 0) + 1

                        confidence = round(float((rf_probas[i] + xgb_probas[i]) / 2) * 100, 2)
                        severity   = classify_severity(label, iso, confidence)

                        # SOC-style incident object — not just a raw prediction
                        incident = {
                            "ts":                 ts_now,
                            "src_ip":             meta["src_ip"],
                            "src_port":           meta["src_port"],
                            "dst_ip":             meta["dst_ip"],
                            "dst_port":           meta["dst_port"],
                            "protocol":           PROTO_NAME.get(meta["protocol"], str(meta["protocol"])),
                            "label":              label,
                            "rf":                 rf,
                            "xgb":                xgb,
                            "confidence":         confidence,
                            "iso":                round(float(iso), 3),
                            "severity":           severity,
                            "recommended_action": recommended_action(label),
                        }
                        self._live["latest_alerts"].insert(0, incident)
                        if len(self._live["latest_alerts"]) > 50:
                            self._live["latest_alerts"].pop()

                        self._session_alerts.insert(0, incident)  # uncapped, for export
                    else:
                        self._live["benign_count"] += 1

                    if rf  != "BENIGN": self._live["rf_threats"]    += 1
                    if xgb != "BENIGN": self._live["xgb_threats"]   += 1
                    if iso < -0.5:      self._live["iso_anomalies"]  += 1

                total = max(self._live["total_flows"], 1)
                self._live["detection_rate"] = round(
                    self._live["threat_count"] / total * 100, 2
                )

                # Timeline point
                self._live["timeline"].append({
                    "t":       ts_now,
                    "threats": self._live["threat_count"],
                    "new":     new_threats,
                })
                if len(self._live["timeline"]) > 120:
                    self._live["timeline"].pop(0)


# ── Flask route registration ──────────────────────────────────────────────────

def init_live_capture(app, models: dict):
    """
    Register /api/live/start, /api/live/stop, /api/live/status routes.
    Call once in app.py after load_all_models().

    The /api/live GET endpoint is registered here and will
    automatically return live capture stats if you point it here.
    """
    from flask import jsonify, request

    engine = LiveCaptureEngine(models)

    @app.route("/api/live/interfaces")
    def live_interfaces():
        """Lists real network interfaces available on this machine."""
        names = []
        try:
            import psutil
            stats = psutil.net_if_stats()
            addrs = psutil.net_if_addrs()
            for name in addrs.keys():
                is_up = stats[name].isup if name in stats else None
                names.append({"name": name, "up": is_up})
            # Sort: up interfaces first, then alphabetically
            names.sort(key=lambda x: (x["up"] is not True, x["name"]))
        except ImportError:
            # Fallback without psutil — best-effort via socket
            try:
                import socket
                names = [{"name": n, "up": None} for n in
                         [i[1] for i in socket.if_nameindex()]]
            except Exception as e:
                return jsonify({"error": f"Could not list interfaces: {e}", "interfaces": []}), 500
        except Exception as e:
            return jsonify({"error": str(e), "interfaces": []}), 500

        return jsonify({"interfaces": names})

    @app.route("/api/live/start", methods=["POST"])
    def live_start():
        data      = request.get_json() or {}
        interface = data.get("interface", "eth0")
        try:
            engine.start(interface)
            return jsonify({"success": True, "interface": interface})
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route("/api/live/stop", methods=["POST"])
    def live_stop():
        engine.stop()
        return jsonify({"success": True})

    @app.route("/api/live/status")
    def live_status():
        stats = engine.get_stats()
        stats["running"] = engine._running
        return jsonify(stats)

    # Single source of truth for /api/live (no replay mode anymore)
    # so the dashboard polls the same URL for both modes
    @app.route("/api/live")
    def live_state():
        stats = engine.get_stats()
        stats["running"] = engine._running
        return jsonify(stats)

    @app.route("/api/live/export")
    def live_export():
        """
        Query params:
          scope  'alerts' (default) — just the incidents from this session
                 'session'          — incidents + summary stats + capture metadata
          fmt    'csv' (default for alerts) | 'json'
        """
        scope = request.args.get("scope", "alerts")
        fmt   = request.args.get("fmt", "csv" if scope == "alerts" else "json")

        data      = engine.get_session_export()
        incidents = data["incidents"]

        if fmt == "csv":
            import csv, io
            from flask import Response
            fieldnames = ["ts", "severity", "label", "src_ip", "src_port", "dst_ip",
                          "dst_port", "protocol", "rf", "xgb", "confidence", "iso",
                          "recommended_action"]
            buf = io.StringIO()
            writer = csv.DictWriter(buf, fieldnames=fieldnames, extrasaction="ignore")
            writer.writeheader()
            for inc in incidents:
                writer.writerow(inc)
            filename = "ai_ids_live_alerts.csv" if scope == "alerts" else "ai_ids_live_session.csv"
            return Response(
                buf.getvalue(),
                mimetype="text/csv",
                headers={"Content-Disposition": f"attachment; filename={filename}"},
            )

        # JSON
        payload  = incidents if scope == "alerts" else data
        filename = "ai_ids_live_alerts.json" if scope == "alerts" else "ai_ids_live_session.json"
        resp = jsonify(payload)
        resp.headers["Content-Disposition"] = f"attachment; filename={filename}"
        return resp

    return engine


# ── Standalone test ───────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse, json

    parser = argparse.ArgumentParser()
    parser.add_argument("--iface",    default="eth0", help="Network interface")
    parser.add_argument("--duration", default=30, type=int, help="Seconds to capture")
    args = parser.parse_args()

    # Minimal stub models for testing feature extraction only
    class StubModels:
        """Use this to test packet capture + feature extraction WITHOUT loading real models."""
        pass

    print(f"[test] Capturing on {args.iface} for {args.duration}s")
    print("[test] NOTE: This test only verifies packet capture + feature extraction.")
    print("[test] For full model predictions, integrate via init_live_capture(app, models).\n")

    tracker = FlowTracker()

    try:
        import asyncio, pyshark
        asyncio.set_event_loop(asyncio.new_event_loop())
        capture = pyshark.LiveCapture(
            interface=args.iface,
            display_filter="ip and (tcp or udp)",
        )

        end_time  = time.time() + args.duration
        pkt_count = 0

        for pkt in capture.sniff_continuously():
            if time.time() > end_time:
                capture.close()
                break
            pkt_count += 1
            try:
                ts  = float(pkt.sniff_timestamp)
                src = str(pkt.ip.src)
                dst = str(pkt.ip.dst)
                if hasattr(pkt, "tcp"):
                    sp, dp    = int(pkt.tcp.srcport), int(pkt.tcp.dstport)
                    flags     = int(pkt.tcp.flags, 16)
                    win       = int(pkt.tcp.window_size)
                    hlen      = int(pkt.tcp.hdr_len)
                    proto     = 6
                else:
                    sp, dp    = int(pkt.udp.srcport), int(pkt.udp.dstport)
                    flags, win, hlen, proto = 0, 0, 8, 17
                try:
                    plen = int(pkt.ip.len)
                except (AttributeError, ValueError):
                    plen = max(0, int(pkt.length) - 14)
                tracker.add_packet(src, dst, sp, dp, proto, ts,
                                   plen, flags, win, hlen)
            except Exception:
                pass

        finished = tracker.expire_flows(time.time() + 999)
        print(f"\nPackets captured : {pkt_count}")
        print(f"Flows completed  : {len(finished)}")
        if finished:
            sample = finished[0]
            print(f"\nSample flow meta: {sample['meta']}")
            print(f"Sample flow features ({len(sample['features'])} columns):")
            for k, v in list(sample["features"].items())[:10]:
                print(f"  {k}: {v}")
            print("  ...")

    except KeyboardInterrupt:
        print("\nStopped.")