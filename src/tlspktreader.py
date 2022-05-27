import argparse
import os
import sys
import pyshark
from datetime import datetime
from dateutil import parser as dtparser
import clienthello as ch
import serverhello as sh
import tlsparser as tlsdec


def readCaptureFile(filename):
    """
    Function that opens a capture file and start processing handshake (unencrypted) packets
    Returns two lists, one for the client packets and the other for the server
    """
    clntpkts = []
    srvrpkts = []
    countpkts = 0
    counths = 0
    pairCHwithSH = 0
    cap = pyshark.FileCapture(filename,display_filter="tls")
    for pkt in cap:
        
        if tlsdec.skipUnrelatedTLSPackets(pkt):
            continue
        #print(pkt.tls)
        if "Client Hello" in str(pkt):
            if "handshake_extensions_key_share_group" in pkt.tls.field_names:                
                pairCHwithSH = pairCHwithSH + 1
                if pairCHwithSH > 1: #discard lonely CHello
                    clntpkts.pop()
                clntpkts.append(ch.parseClientHello(pkt))                
        if "Server Hello" in str(pkt):
            if "handshake_extensions_key_share_group" in pkt.tls.field_names:
                srvrpkts.append(sh.parseServerHello(pkt))                
                pairCHwithSH = 0
        countpkts = countpkts + 1

    cap.close()
    counths = len(clntpkts)
    print("End of CHello/SHello processing. CH: " +  str(len(clntpkts))  +  " SH: "+  str(len(srvrpkts)) + " Now for authentication packets...")
    return clntpkts,srvrpkts, counths, countpkts

def getHandshakes(clientpkts,serverpkts,counths, authpkts):
    """
    After parsing packets, it arranges them into pairs (ch-sh)
    for reporting purposes. Result:
    [
        clntGroup, KEXsize, CHelloSize, SHelloSize,hsTotalSize,hsCapTotalSize
        if tls key log file is provided, it adds auth-related results
    ]
    """
    handshakes = []
    if len(clientpkts)!=len(serverpkts):
        print("Warning: different number of client/server handshake packets. Check your pcap file.")
        print("CHello: " + str(len(clientpkts)) + " SHello:" + str(len(serverpkts)))
    
    if len(authpkts) < len(serverpkts):  #got server hello that does not have certificates?
        print("Considering only the handshakes with server certificates (resumption is not counted)")
        counths = len(authpkts)


    for i in range(int(counths)):
        srvGroup = int(serverpkts[i][0][0])
        clntGroup,keyshareSize = ch.getEquivalentGroup(clientpkts[i][0],srvGroup)

        if clntGroup == -1:
            print("Error: Catch ya later, Wrong (KEX) group dudes! (Client:"+str(clntGroup) + " and server:" + str(srvGroup) + ").")
            return []
        #KEX data
        KEXsize = int(keyshareSize)+int(serverpkts[i][0][1])
        CHelloSize = int(clientpkts[i][0][-1])
        SHelloSize = int(serverpkts[i][0][-1])
        hsTotalSize = CHelloSize +SHelloSize     #+auth messages?
        hsCapTotalSize = int(clientpkts[i][1][3])+int(serverpkts[i][1][3])    #+auth messages?
        
        dt1 = dtparser.parse(clientpkts[i][1][-3].show)        

        #Auth data (only if keys are provided)
        if not authpkts:
            handshakes.append([clntGroup, KEXsize, CHelloSize, SHelloSize,hsTotalSize,hsCapTotalSize])
        else:
            #Auth algorithm | Handshake Signature size (bytes) 
            #print(authpkts[i])
            if (i >= len(authpkts)):
                continue
            AuthAlgo = authpkts[i][1][0][0]
            HSSignatureSize = authpkts[i][1][0][1]
            CertificatesSize = int(authpkts[i][0][0][1])
            HSTimeEpoch = authpkts[i][2][1][-1]
            dt2 = dtparser.parse(authpkts[i][2][1][-2].show)            
            HSTime = dt2 - dt1
                                                                                #Finished Length
            hsTotalSize = hsTotalSize + HSSignatureSize + CertificatesSize + int(authpkts[i][2][0][0])
            handshakes.append([clntGroup, KEXsize, CHelloSize, SHelloSize,hsTotalSize,
                                hsCapTotalSize,AuthAlgo,HSSignatureSize,CertificatesSize,
                                HSTimeEpoch,HSTime])
        
    return handshakes
        

def printStats(handshakes, authflag):
    """
    Prints some statistics and information about the handshakes present in the capture file used
    """
    if not handshakes: 
        print("No TLS handshake to analyze.")
        return

    i = 0
    totalsize = 0
    totalhstime = dtparser.parse("00:00:00")
    totalhstime = totalhstime - totalhstime #nice way to start from 0
    for h in handshakes:
        i = i + 1        
        print("------------------------- Cost statistics handshake nº"+ str(i) + " (in bytes):")
        print("KEX algorithm | KEX size (bytes) | CHELLO size (bytes) | SHELLO size (bytes) | Auth algorithm          | Handshake Signature size (bytes) | Certificates size (bytes) |")
        print (f"{h[0]:13} |",
               f"{h[1]:16} |",
               f"{h[2]:19} |",
               f"{h[3]:19} |", end='')               
        if authflag:
            print (f"{h[6]:23} |",
                   f"{h[7]:32} |",
                   f"{h[8]:25} |", end='')
        
            hstime = (h[-1]) 
            hstimeEpoch = float(h[-2])    
            #print("H:"+str(totalhstime))
            totalhstime = totalhstime + hstime

        totalsize = totalsize + int(h[4]) 
        print("\n")
        print("Handshake KEX+Auth total (bytes): " + str(int(h[4])))
        if authflag:
            print("Handshake time (s): " + str((hstime)) + " ; epoch: "+ str((hstimeEpoch)))
        print("---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------")
    
    print("")
    print("Summary:")
    print("Number of  Handshakes  | Total HS Size (bytes) | HS Time Cumulative")
    print (f"{i:22} |", f"{totalsize:21} | ",f"{str(totalhstime):18} ")
    #print (f"{i:22} |", f"{totalsize:21} | ")


 
if __name__ == '__main__':
    """
        TLS Analyzer starting point
    """
    print("""  ________   _____    __  __                __     __          __           ___                __                     
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
        authflag = False
        #start with public parts of the handshake
        clientpkts, serverpkts, counths, countpkts = readCaptureFile(filename)
        authpkts = []        
        # check for keys
        if args.tlskey is not None:
            authflag = True
            authpkts = tlsdec.pysharkDecryptHandshakeServerAuth(countpkts, filename, args.tlskey)
        printStats(getHandshakes(clientpkts,serverpkts,counths,authpkts),authflag)
    print("End of processing.")
