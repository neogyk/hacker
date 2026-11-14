"""
WiresharkTracer — capture the communication with the target LLM.

Two layers, because the target is reached over HTTPS:
  * Packet layer (best effort): if tshark/dumpcap/tcpdump exists AND the process
    can capture, it writes a .pcap of traffic to the target host. Over TLS this
    is ciphertext + metadata (SNI, sizes, timing) unless SSLKEYLOGFILE is honored.
  * Flow layer (always works): an application-level log of every request/response
    exchanged with the LLM — the actual readable "data from the LLM".

It degrades gracefully: no capture tool or no privileges -> flow layer only, with
the reason recorded. Authorized red-team use on your own traffic only.
"""

from __future__ import annotations

import json
import os
import shutil
import signal
import subprocess
import time
from pathlib import Path
from typing import Optional

HERE = Path(__file__).parent
CAP_DIR = HERE / "logs" / "captures"


class WiresharkTracer:
    def __init__(self, target_host: str, label: Optional[str] = None,
                 outdir: Path = CAP_DIR):
        self.host = target_host
        self.label = label or time.strftime("session_%Y%m%d_%H%M%S")
        outdir.mkdir(parents=True, exist_ok=True)
        self.pcap = outdir / f"{self.label}.pcap"
        self.flowlog = outdir / f"{self.label}.flows.jsonl"
        self.keylog = outdir / f"{self.label}.keys.log"
        self.proc: Optional[subprocess.Popen] = None
        self.mode = "flow-only"
        self.note = ""
        self.n_flows = 0
        self.n_bytes = 0

    # -- lifecycle --------------------------------------------------------- #
    def start(self) -> "WiresharkTracer":
        # Let TLS libs that honor it drop session keys (so a pcap is decryptable).
        os.environ.setdefault("SSLKEYLOGFILE", str(self.keylog))
        cap = shutil.which("dumpcap") or shutil.which("tshark") or shutil.which("tcpdump")
        if not cap:
            self.note = "no tshark/dumpcap/tcpdump found — flow-level capture only"
            return self
        try:
            if cap.endswith("tcpdump"):
                cmd = [cap, "-i", "any", "-w", str(self.pcap), "host", self.host]
            else:  # tshark / dumpcap
                cmd = [cap, "-i", "any", "-f", f"host {self.host}", "-w", str(self.pcap)]
            self.proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL,
                                         stderr=subprocess.PIPE)
            time.sleep(0.5)
            if self.proc.poll() is not None:   # died immediately (perms?)
                err = (self.proc.stderr.read().decode()[:160] if self.proc.stderr else "")
                self.proc = None
                self.note = f"packet capture unavailable ({err.strip() or 'permission denied'}); flow-level only"
            else:
                self.mode = "pcap+flow"
                self.note = f"capturing packets with {Path(cap).name}"
        except Exception as e:  # noqa: BLE001
            self.proc = None
            self.note = f"capture failed to start ({e}); flow-level only"
        return self

    def capture(self, direction: str, payload: dict) -> None:
        """Record one application-level message (request or response)."""
        rec = {"ts": time.strftime("%H:%M:%S"), "host": self.host,
               "direction": direction, **payload}
        blob = json.dumps(rec, ensure_ascii=False)
        self.n_flows += 1
        self.n_bytes += len(blob)
        with self.flowlog.open("a") as f:
            f.write(blob + "\n")

    def capture_exchange(self, request: dict, response: dict) -> None:
        self.capture("c2s", {"request": request})
        self.capture("s2c", {"response": response})

    def stop(self) -> dict:
        packets = None
        if self.proc is not None:
            try:
                self.proc.send_signal(signal.SIGINT)
                self.proc.wait(timeout=5)
            except Exception:  # noqa: BLE001
                self.proc.kill()
            packets = self._pcap_packets()
        return self.summary(packets)

    # -- helpers ----------------------------------------------------------- #
    def _pcap_packets(self) -> Optional[int]:
        capinfos = shutil.which("capinfos")
        if capinfos and self.pcap.exists():
            try:
                out = subprocess.run([capinfos, "-c", str(self.pcap)],
                                     capture_output=True, text=True, timeout=10).stdout
                for line in out.splitlines():
                    if "Number of packets" in line:
                        return int(line.split("=")[-1].strip().replace(",", ""))
            except Exception:  # noqa: BLE001
                return None
        return None

    def summary(self, packets: Optional[int] = None) -> dict:
        return {
            "mode": self.mode, "note": self.note, "host": self.host,
            "flows": self.n_flows, "flow_bytes": self.n_bytes,
            "packets": packets,
            "pcap": str(self.pcap) if self.mode.startswith("pcap") else None,
            "flowlog": str(self.flowlog),
        }


if __name__ == "__main__":
    import btm
    from urllib.parse import urlparse
    host = urlparse(btm.API).hostname
    t = WiresharkTracer(host, label="selftest").start()
    print("start:", t.note)
    t.capture_exchange({"message": "hello riley"}, {"reply": "hi", "tool_calls": []})
    print("summary:", json.dumps(t.stop(), indent=2))
