# TLS 1.3 Handshake Analyzer

TLS 1.3 Handshake analyzer. Explore security information and performance from TLS captures.

## Requirements

You can either use Docker or build and run on your own with:

- `sudo apt install tshark`
- `sudo pip3 install -r src/requirements.txt

Make sure you have full permissions in the capture file. There is no live-capture mode implemented (at least, not yet), so you need a pcap file. 


## Main Features

- Gives a report showing the information (focusing on costs) of TLS 1.3 handshake messages (and cryptographic objects)
- Checks for insecure ciphersuites, based on [ciphersuite.info](https://ciphersuite.info)
- Checks for Encrypted Client Hello (ECH) extension.

## Usage

There are two interfaces: CLI and the web interface.

### Command-Line Interface

Execute like this: `python3 src/main.py --pcap ../captures/tls13-rfc8446.pcap`

Flags: 
- `--pcap` path to the pcap/pcapng capture file
- `--tlskey` path to the TLS Keylog file.

### Web Interface

Execute the app: `python3 src/main.py --ide`. It will launch a Dash app in http://127.0.0.1:8050/. Deploy instructions are out of the scope of this README, but here is an [example](https://www.digitalocean.com/community/tutorials/how-to-deploy-a-flask-application-on-an-ubuntu-vps). Alternatively, you can use Docker as shown below.

### Docker

Build the image with `docker build . -t tlsanalyzer` then run `docker run -p 8050:8050 tlsanalyzer:latest --ide` and go to `http://localhost:8050` to use the web interface. Also, you can use the CLI with `docker run tlsanalyzer:latest --pcap ../captures/tls13-rfc8446.pcap`.


## Output Information

The analyzer computes:
- Sizes: considering KEX objects (keyshare) and Authentication objects: Certificates (length), Certificate Verify (length), Finished (length)
- Timings: subtracts timings (from wireshark capture time): Server Finished message (time) - Client Hello message (time).

The analyzer search for in-order pairs {CHello,SHello} to find TLS 1.3 handshakes and extracts sizes. Some types (e.g., resumption) are not counted. The summary results counts how many full handshakes were found and sum their sizes and time.

## Known issues

Some pcap files are not dealt consistently between different tshark builds; be sure to use latest versions.

Suggestions and contributions are welcome!
