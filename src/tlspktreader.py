import argparse
import os
import sys
import os
import pyshark
import clienthello as ch
import serverhello as sh


def readCaptureFile(filename):
    """
    Function that opens a capture file and start processing packets
    Returns two lists, one for the client packets and the other for the server
    """
    clntpkts = []
    srvrpkts = []
    countpkts = 0    
    cap = pyshark.FileCapture(filename,display_filter="tls")
    for pkt in cap:        
        if "Client Hello" in str(pkt.tls):           
            clntpkts.append(ch.parseClientHello(pkt))
            countpkts = countpkts + 1
        if "Server Hello" in str(pkt.tls):        
            srvrpkts.append(sh.parseServerHello(pkt))
            countpkts = countpkts + 1

    return clntpkts,srvrpkts, countpkts

def getHandshakes(clientpkts,serverpkts,countpkts):
    """
    After parsing packets, it arranges them into pairs (ch-sh)
    for reporting purposes. Result:
    [
        clntGroup, KEXsize, CHelloSize, SHelloSize,hsTotalSize,hsCapTotalSize
    ]
    """
    handshakes = []    
    if len(clientpkts)!=len(serverpkts):
        print("Warning: different number of client/server handshake packets. Check your pcap file.")
    
    for i in range(int(countpkts/2)):
        clntGroup = int(clientpkts[i][0][0])
        srvGroup = int(serverpkts[i][0][0])
        if clntGroup != srvGroup:
            print("Error: Catch ya later, Wrong (KEX) group dudes! ( "+str() + "and " + str() + ").")
            return []
        #KEX data
        KEXsize = int(clientpkts[i][0][2])+int(serverpkts[i][0][1])
        CHelloSize = int(clientpkts[i][0][-1])
        SHelloSize = int(serverpkts[i][0][-1])
        hsTotalSize = int(clientpkts[i][1][2])+int(serverpkts[i][1][2])    #+auth messages?
        hsCapTotalSize = int(clientpkts[i][1][3])+int(serverpkts[i][1][3])    #+auth messages?
        #Auth data

        #result
        handshakes.append([clntGroup, KEXsize, CHelloSize, SHelloSize,hsTotalSize,hsCapTotalSize])    
    return handshakes
        

def printStats(handshakes):
    """
    Prints some statistics and information about the handshakes present in the capture file used
    """
    if not handshakes: 
        print("No TLS handshake to analyze.")
        return

    i = 0
    totalsize = 0
    for h in handshakes:
        i = i + 1        
        print("------------------------- Cost statistics handshake nº"+ str(i) + " (in bytes):")
        print("KEX algorithm | KEX size (bytes) | CHELLO size (bytes) | SHELLO size (bytes) | Auth algorithm | Handshake Signature size (bytes) | Server-cert size (bytes) | Cert-chain size (bytes) |")
        print (f"{h[0]:13} |",
               f"{h[1]:16} |",
               f"{h[2]:19} |",
               f"{h[3]:19} |")               


        totalsize = totalsize + int(h[4]) #+ server auth messages
        print("")
        print("Handshake total (bytes): " + str(int(h[4])))
        print("---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------")
    
    print("")
    print("Summary:")
    print("Number of  Handshakes  | Total Size (bytes) |")
    print (f"{i:22} |", f"{totalsize:18} |")


 
if __name__ == '__main__':
    """
        TLS Analyzer starting point
    """
    print("""   ________   _____    __  __                __     __          __           ___                __                     
 /_  __/ /  / ___/   / / / /___ _____  ____/ /____/ /_  ____ _/ /_____     /   |  ____  ____ _/ /_  ______  ___  _____
  / / / /   \__ \   / /_/ / __ `/ __ \/ __  / ___/ __ \/ __ `/ //_/ _ \   / /| | / __ \/ __ `/ / / / /_  / / _ \/ ___/
 / / / /______/ /  / __  / /_/ / / / / /_/ (__  ) / / / /_/ / ,< /  __/  / ___ |/ / / / /_/ / / /_/ / / /_/  __/ /    
/_/ /_____/____/  /_/ /_/\__,_/_/ /_/\__,_/____/_/ /_/\__,_/_/|_|\___/  /_/  |_/_/ /_/\__,_/_/\__, / /___/\___/_/     
                                                                                             /____/                   
  """)
    parser = argparse.ArgumentParser(description='PCAP Pyshark reader')
    parser.add_argument('--pcap', metavar='<pcap capture file>',
                        help='pcap file to parse', required=True)
    args = parser.parse_args()
    
    filename = args.pcap
    if not os.path.isfile(filename):
        print('"{}" does not exist.'.format(filename), file=sys.stderr)
    else:
        clientpkts, serverpkts, countpkts = readCaptureFile(filename)
        printStats(getHandshakes(clientpkts,serverpkts,countpkts))
    print("End of processing.")
