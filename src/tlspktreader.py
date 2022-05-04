import argparse
import os
import sys
import os
import pyshark
import clienthello as ch
import serverhello as sh


def readCaptureFile(filename):
    clntpkts = []
    srvrpkts = []    
    cap = pyshark.FileCapture(filename,display_filter="tls")
    for pkt in cap:
        if "Client Hello" in str(pkt.tls):    
            clntpkts.append(ch.parseClientHello(pkt))
        if "Server Hello" in str(pkt.tls):        
            srvrpkts.append(sh.parseServerHello(pkt))

    return clntpkts,srvrpkts


def printStats(clientpkts,serverpkts):
    handshakes = []
    for l in clientpkts:
        pass
    for l in serverpkts:
        pass

    i = 0
    for h in handshakes:
        print("Cost statistics handshake "+ str(++i))
        print("KEX algorithm | KEX size (bytes) | CHELLO size (bytes) | SHELLO size (bytes)")

        print("Auth algorithm | Auth size (bytes) | Handshake Signature size (bytes) | Server-cert size (bytes) | Cert-chain size (bytes)")

    print("Summary: Handshake number | Total Size (bytes)")

    print("Full cost: " + " bytes.")

 
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='PCAP Pyshark reader')
    parser.add_argument('--pcap', metavar='<pcap capture file>',
                        help='pcap file to parse', required=True)
    args = parser.parse_args()
    
    filename = args.pcap
    if not os.path.isfile(filename):
        print('"{}" does not exist.'.format(filename), file=sys.stderr)
    else:
        clientpkts, serverpkts = readCaptureFile(filename)
        printStats(clientpkts, serverpkts)

