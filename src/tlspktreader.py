import argparse
import os
import sys
import pyshark
import statistics
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

    #match client random with server session id, otherwise discard chello
    for cpkt in clientpkts:
        discard = True    
        crandom = cpkt[1][-1]
        for i in range(counths):
        #for spkt in serverpkts:
            spkt = serverpkts[i]
            if (crandom  == spkt[1][-1]):
                srvGroup = int(spkt[0][0])
                clntGroup,keyshareSize = ch.getEquivalentGroup(cpkt[0],srvGroup)
                if clntGroup == -1:
                    print("Error: Catch ya later, Wrong (KEX) group dudes! (Client:"+str(clntGroup) + " and server:" + str(srvGroup) + ").")
                    break
                
                #KEX data
                KEXsize = int(keyshareSize)+int(spkt[0][1])
                CHelloSize = int(cpkt[0][-1])
                SHelloSize = int(spkt[0][-1])
                hsTotalSize = CHelloSize +SHelloSize     
                hsCapTotalSize = int(cpkt[1][3])+int(spkt[1][3])
                
                dt1 = float(cpkt[1][-2].show) #epoch time   

                if not authpkts:
                    handshakes.append([clntGroup, KEXsize, CHelloSize, SHelloSize,hsTotalSize,hsCapTotalSize])
                    discard = False
                else:
                    #now get corresponding server certificate
                    #                for j in range(i,len(authpkts)):
                    for apkt in authpkts:
                        
                        if apkt[1][1][0] != spkt[1][0]:
                            continue
                        
                        #if spkt[1][0] != authpkts[i][1][1][0]: #IP checking (i might not be the same for SHello...)
                            #server hello without cert, assuming in-order packets (should be)
                            #print("Skipping server hello without subsequent certificate message (at "+str(spkt[1][4])+").")
                            #break
                        discard = False

                        #TODO: could search for insecure ciphersuite usage (not checking advertising):
                        #listUnsafeCiphersuites = checkUnsafeCiphersuiteAPI(spkt[1][-2])

                        #Auth data (only if keys are provided)    
                        #print(authpkts[i])
                        AuthAlgo = authpkts[i][1][0][0]
                        HSSignatureSize = authpkts[i][1][0][1]
                        CertificatesSize = int(authpkts[i][0][0][1])
                        FinishedSize = int(authpkts[i][2][0][0])
                        HSTime = authpkts[i][2][1][-2]  
                        HSTimeEpoch = float(authpkts[i][2][1][-1].show) - dt1
                                                                                            #Finished Length
                        hsTotalSize = hsTotalSize + HSSignatureSize + CertificatesSize + FinishedSize
                        
                        handshakes.append([clntGroup, KEXsize, CHelloSize, SHelloSize,hsTotalSize,
                                            hsCapTotalSize,AuthAlgo,HSSignatureSize,CertificatesSize,FinishedSize,
                                            HSTimeEpoch,HSTime])
                        break
        if discard:
            print("Discard CHello (" + str(crandom) + "): couldn't find matching SHello session ID or Certificate")

#    for i in range(int(counths)):
#        srvGroup = int(serverpkts[i][0][0])
#        clntGroup,keyshareSize = ch.getEquivalentGroup(clientpkts[i][0],srvGroup)

#        if clntGroup == -1:
#            print("Error: Catch ya later, Wrong (KEX) group dudes! (Client:"+str(clntGroup) + " and server:" + str(srvGroup) + ").")
#            return []
        
        
        #KEX data
#        KEXsize = int(keyshareSize)+int(serverpkts[i][0][1])
#        CHelloSize = int(clientpkts[i][0][-1])
#        SHelloSize = int(serverpkts[i][0][-1])
#        hsTotalSize = CHelloSize +SHelloSize     #+auth messages?
#        hsCapTotalSize = int(clientpkts[i][1][3])+int(serverpkts[i][1][3])    #+auth messages?
        
#        dt1 = float(clientpkts[i][1][-2].show) #epoch time   

        #Auth data (only if keys are provided)
#        if not authpkts:
#            handshakes.append([clntGroup, KEXsize, CHelloSize, SHelloSize,hsTotalSize,hsCapTotalSize])
#        else:
            #Auth algorithm | Handshake Signature size (bytes) 
            #print(authpkts[i])
#            if (i >= len(authpkts)):
#                continue
#            AuthAlgo = authpkts[i][1][0][0]
#            HSSignatureSize = authpkts[i][1][0][1]
#            CertificatesSize = int(authpkts[i][0][0][1])
#            HSTime = authpkts[i][2][1][-2]            
#            HSTimeEpoch = float(authpkts[i][2][1][-1].show) - dt1
                                                                                #Finished Length
#            hsTotalSize = hsTotalSize + HSSignatureSize + CertificatesSize + int(authpkts[i][2][0][0])
#            handshakes.append([clntGroup, KEXsize, CHelloSize, SHelloSize,hsTotalSize,
#                                hsCapTotalSize,AuthAlgo,HSSignatureSize,CertificatesSize,
#                                HSTimeEpoch,HSTime])
        
    return handshakes
        

def printStats(handshakes, authflag):
    """
    Prints some statistics and information about the handshakes present in the capture file used
    """
    if not handshakes: 
        print("Could not found TLS 1.3 handshakes with same session ID and/or server certificates to analyze.")
        return

    i = 0
    totalsize = 0
    stdevsamples = []
    totalhstime = 0
    for h in handshakes:
        i = i + 1        
        print("------------------------- Cost statistics handshake nº"+ str(i) + " (in bytes):")
        print("KEX algorithm | KEX size (bytes) | CHELLO size (bytes) | SHELLO size (bytes) | Auth algorithm          | Handshake Signature size (bytes) | Certificates size (bytes) | Finished size (bytes)")
        print (f"{h[0]:13} |",
               f"{h[1]:16} |",
               f"{h[2]:19} |",
               f"{h[3]:19} |", end='')               
        if authflag:
            print (f"{h[6]:24} |",
                   f"{h[7]:32} |",
                   f"{h[8]:25} |",
                   f"{h[9]:19} |", end='')
        
            #hstime = (h[-1]) 
            hstimeEpoch = float(h[-2])
            #print("H:"+str(totalhstime))
            totalhstime = totalhstime + hstimeEpoch
            stdevsamples.append(hstimeEpoch)
        totalsize = totalsize + int(h[4]) 
        print("\n")
        print("CHello and SHello cost: " + str(h[2]+h[3]))
        print("Authentication cost (Certificates, CertificateVerify, Finished): " + str(h[7]+h[8]+h[9]))
        print("Handshake KEX+Auth total (bytes): " + str(int(h[4])))
        if authflag:
            print("Handshake time (s): " + str((hstimeEpoch))) #+ " ; epoch: "+ str((hstimeEpoch)))
        print("---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------")
    
    hstimeprint = "{:.6f}".format(totalhstime)
    avgprint = "{:.6f}".format(totalhstime/len(handshakes))
    stdevprint = "{:.6f}".format(statistics.stdev(stdevsamples))
    print("")
    print("Summary:")
    print("Number of  Handshakes  | Total HS Size (bytes) | HS Time Cumulative (s) | Avg HS Time (s) | Stdev HS Time (s)")
    print (f"{i:22} |", f"{totalsize:21} | ",
            f"{hstimeprint:21} | ",
            f"{avgprint:14} | ",
            f"{stdevprint:14} |"  )
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
    parser.add_argument('--avgtime', metavar='<number of handshakes>',
                        help='number of handshakes for average timings', required=False)

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
