import argparse
import os
import sys
import os
import pyshark

#cap = pyshark.FileCapture(
#    'google.pcap', use_json=True, include_raw=True,
#    override_prefs={'ssl.keylog_file': os.path.abspath('sslkeys_google.log')},
#    debug=True)


#Requires
#sudo apt install tshark
#sudo pip3 install pyshark

def parseClientHello(pkt):
    pass

def parseServerHello(pkt):
    pass

def readCaptureFile(filename):
    count = 0
    chelloNumber = 0
    cap = pyshark.FileCapture(filename,display_filter="tls")
    for pkt in cap:
        count = count + 1
        if "Client Hello" in str(pkt.tls):
            chelloNumber = chelloNumber + 1
        if "Server Hello" in str(pkt.tls):        
            print(pkt.tls)

    print("Number of TLS Client Hello Packets:"+str(chelloNumber))
 
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='PCAP Pyshark reader')
    parser.add_argument('--pcap', metavar='<pcap capture file>',
                        help='pcap file to parse', required=True)
    args = parser.parse_args()
    
    filename = args.pcap
    if not os.path.isfile(filename):
        print('"{}" does not exist.'.format(filename), file=sys.stderr)
    else:
        readCaptureFile(filename)

