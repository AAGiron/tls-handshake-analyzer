# TLS Handshake Analyzer

TLS 1.3 Handshake analyzer

## Requirements

- `sudo apt install tshark`
- `sudo pip3 install pyshark`

## Usage

There is no live-capture mode implemented (at least, not yet), so you need a pcap file. 

Execute like this: `python3 tlspktreader.py --pcap ../captures/tls13-rfc8446.pcap`

It will give a report showing the information (focusing on costs) of some TLS handshake objects.

Make sure you have full permissions in the capture file.

Flags: 
- `--pcap` path to the pcap/pcapng capture file
- `--tlskey` path to the TLS Keylog file.


## Output Information

The analyzer computes:
- Sizes: considering KEX objects (keyshare) and Authentication objects: Certificates (length), Certificate Verify (length), Finished (length)
- Timings: subtracts timings (from wireshark capture time): Server Finished message (time) - Client Hello message (time).

The analyzer search for in-order pairs {CHello,SHello} to find TLS 1.3 handshakes and extracts sizes. The summary results counts how many handshakes were found and sum their sizes and time.

## Known issues

Some pcap files are not dealt consistently between different tshark builds; be sure to use latest versions.

The code needs improvements, e.g., readability, optimizations. (In progress).
