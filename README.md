# TLS Handshake Analyzer

TLS 1.3 Handshake analyzer (in progress)

## Requirements

- `sudo apt install tshark`
- `sudo pip3 install pyshark`
- `sudo pip3 install pycryptodomex`

## Usage

There is no live-capture mode implemented (at least, not yet), so you need a pcap file. 

Execute like this: `python3 tlspktreader.py --pcap ../captures/tls13-rfc8446.pcap`

It will give a report showing the information (focusing on costs) of some TLS handshake objects.

Make sure you have full permissions in the capture file.


## Additional Information

The analyzer search for pairs {CHello,SHello} to find TLS (1.3 currently) handshakes and extracts sizes. For now, authentication-related sizes (e.g., certificates) are not being computed. The summary results counts how many handshakes were found and sum their sizes. (The total size is computed with pysharpkt.frame_info.cap_len

More to come.
