import argparse
import os
import sys
import pyshark
import clienthello as ch
import serverhello as sh
import tlsdecryptor as tlsdec

def readCaptureFile(filename):
    """
    Function that opens a capture file and start processing handshake (unencrypted) packets
    Returns two lists, one for the client packets and the other for the server
    """
    clntpkts = []
    srvrpkts = []
    countpkts = 0    
    counths = 0
    cap = pyshark.FileCapture(filename,display_filter="tls")
    for pkt in cap:        
        if "Client Hello" in str(pkt.tls):
            if "handshake_extensions_key_share_group" in pkt.tls.field_names:   
                clntpkts.append(ch.parseClientHello(pkt))
                counths = counths + 1            
        if "Server Hello" in str(pkt.tls):    
            if "handshake_extensions_key_share_group" in pkt.tls.field_names:
                srvrpkts.append(sh.parseServerHello(pkt))
                counths = counths + 1            
        countpkts = countpkts + 1            

    cap.close()
    return clntpkts,srvrpkts, counths, countpkts

def getHandshakes(clientpkts,serverpkts,counths, authpkts):
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
    
    for i in range(int(counths/2)):
        srvGroup = int(serverpkts[i][0][0])
        clntGroup,keyshareSize = ch.getEquivalentGroup(clientpkts[i][0],srvGroup)

        if clntGroup == -1:
            print("Error: Catch ya later, Wrong (KEX) group dudes! (Client:"+str(clntGroup) + " and server:" + str(srvGroup) + ").")
            return []
        #KEX data
        KEXsize = int(keyshareSize)+int(serverpkts[i][0][1])
        CHelloSize = int(clientpkts[i][0][-1])
        SHelloSize = int(serverpkts[i][0][-1])
        hsTotalSize = int(clientpkts[i][1][2])+int(serverpkts[i][1][2])    #+auth messages?
        hsCapTotalSize = int(clientpkts[i][1][3])+int(serverpkts[i][1][3])    #+auth messages?
        
        #Auth data (only if keys are provided)
        if not authpkts:
            pass

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
    ### Flags
    parser = argparse.ArgumentParser(description='PCAP Pyshark reader')
    parser.add_argument('--pcap', metavar='<pcap capture file>',
                        help='pcap file to parse', required=True)
    parser.add_argument('--tlskey', metavar='<tls key log file>',
                        help='key log file to decrypt tls messages', required=False)
    args = parser.parse_args()
    
    filename = args.pcap
    if not os.path.isfile(filename):
        print('"{}" does not exist.'.format(filename), file=sys.stderr)
    else:        
        #start with public parts of the handshake
        clientpkts, serverpkts, counths, countpkts = readCaptureFile(filename)
        authpkts = []        
        # check for keys
        if args.tlskey is not None:
            #get randoms from client packets
            randoms =  tlsdec.extract_client_randoms(clientpkts)
            #get negotiated ciphersuite from server packet 
            ciphersuites = tlsdec.extractCiphersuite(serverpkts)
            allkeys = tlsdec.read_key_log_file(args.tlskey)                
            authpkts = tlsdec.decryptHandshakeServerAuth(countpkts, allkeys,randoms,ciphersuites,filename)            
        printStats(getHandshakes(clientpkts,serverpkts,counths,authpkts))
    print("End of processing.")
