# ARP-Spoof-Detection-Algorithm-Using-ICMP-Protocol
This repository contains a Python and Scapy implementation of the ICMP-based
ARP spoof detection paper that was reproduced and corrected in spring 2018. It
is a useful security lab project, especially if you want to understand packet
inspection and simple spoofing detection heuristics.

## Quick start

1. Install Python 3 and the networking tools you use for lab work.
2. Run the project in an isolated VM or test network.
3. Use Wireshark or similar tooling to observe the packets and verify the
   detection logic.

## If you modernize it later

A much friendlier 2026 version would pair `Scapy` with a `FastAPI` dashboard,
structured logging, and a small live web UI for alerts. If you want deeper
network telemetry, consider `Zeek` or `Suricata` alongside the Python detector.
Spring 2018
Successfully implemented the IEEE paper publication “ARP Spoof Detection Algorithm Using ICMP Protocol”. Found shortcomings in the author’s implementation of this paper and corrected them Language, packages and tools used: VMware, Scapy, Python, Wireshark, dsniff
