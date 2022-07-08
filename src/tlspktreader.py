import argparse
import os
import sys
import pyshark
import statistics
import tlsparser as tlspar
from tlsobj.handshake import Handshake 
from tlsobj.chello import CHello
from tlsobj.serverdata import Serverdata
from tlsobj.certificate import Certificate
from tlsobj.certificateverify import Certificateverify
from tlsobj.finished import Finished

#used for Finished packets
def matchSource(finishedOb,HSob):
    if HSob is not None:
        if finishedOb.pktinf.srcip == HSob.pktinf.srcip and \
            finishedOb.pktinf.srcport == HSob.pktinf.srcport:
            return True
    return False


def readCaptureFile(filename, tlskeyfilename):
    """
        Assumes in-order TLS packets
    """
    hslist = []

    if tlskeyfilename is not None:
        cap = pyshark.FileCapture(filename,
                                override_prefs={'tls.keylog_file': tlskeyfilename}, display_filter="tls")#, use_json=True
    else:
        cap = pyshark.FileCapture(filename, display_filter="tls") #, use_json=True
        #adding a search for CH-SH pairs when no keylog file is provided
        hslist = tlspar.getTLSPublicData(cap)
        return hslist


    #temp handshake object
    hs = Handshake()
    sfinished = True
    hspackets = 0
    print("Start full parsing (pcap + keylog)...")
    for pkt in cap:

        if tlspar.skipUnrelatedTLSPackets(pkt):
            continue

        tlsobjects = tlspar.getTLSObjectList(pkt)
        #print(tlsobjects)
        for ob in tlsobjects:
            if isinstance(ob, CHello):
                setattr(hs, "chello", ob)
                setattr(hs, "beginhstime", ob.pktinf.epoch)
            elif isinstance(ob, Serverdata):
                setattr(hs, "serverdata", ob)
                setattr(hs, "ciphersuite", ob.hsciphersuite)
            elif isinstance(ob, Certificate):                
                setattr(hs, "certificatedata", ob)
            elif isinstance(ob, Certificateverify):
                setattr(hs, "certificateverify", ob)
            elif isinstance(ob, Finished):
                if matchSource(ob, hs.serverdata):  #HS time based on server finished
                    setattr(hs, "finished", ob)
                    if hasattr(hs.beginhstime, 'show'):
                        time = float(ob.pktinf.epoch.show) - float(hs.beginhstime.show)     
                        setattr(hs, "hstime", time * 1000) #ms                
                elif matchSource(ob, hs.chello):
                    setattr(hs, "cfinished", ob) 
                
        if (hs.hasKEXandAuthData()):            
            hs.setSize()

        if hs.verifyCorrectness():
            hslist.append(hs)
            hs = Handshake()


    return hslist


def printStats(handshakes):
    """
    Prints some statistics and information about the handshakes present in the capture file used
    """
    if not handshakes: 
        print("Could not found TLS 1.3 handshakes to analyze.")
        return

    i = 0
    totalsize = 0
    stdevsamples = []
    totalhstime = 0
    for h in handshakes:
        i = i + 1        
        print("------------------------- Cost statistics handshake nº"+ str(i) + " (in bytes):")
        print("KEX algorithm        | KEX size (bytes) | CHELLO size (bytes) | SHELLO size (bytes) | Auth algorithm          | Handshake Signature size (bytes) | Certificates size (bytes) | Finished size (bytes)")
        print (f"{h.serverdata.getKEXNameFromGroup():20} |",
               f"{h.chello.keyshareLength:16} |",
               f"{h.chello.size:19} |",
               f"{h.serverdata.size:19} |", end='')               
        print (f"{h.certificateverify.signatureAlgo:24} |",
               f"{h.certificateverify.signatureLength:32} |",
               f"{h.certificatedata.certsLength:25} |",
               f"{h.finished.size:19} |", end='')
                
        totalhstime = totalhstime + h.hstime
        stdevsamples.append(h.hstime)
        totalsize = totalsize + int(h.hssize) 
        print("\n")        
        print("Handshake KEX+Auth total (bytes): " + str(h.hssize))        
        print("Handshake time (ms): " + str((h.hstime))) #+ " ; epoch: "+ str((hstimeEpoch)))
        print("-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------")
    
    hstimeprint = "{:.2f}".format(totalhstime)
    avgprint = "{:.2f}".format(totalhstime/len(handshakes))
    try:
        stdevprint = "{:.2f}".format(statistics.stdev(stdevsamples))
    except statistics.StatisticsError:
        stdevprint = float("NaN")
    print("")
    print("Summary:")
    print("Number of  Handshakes  | Total HS Size (bytes) | HS Time Cumulative (ms) | Avg HS Time (ms) | Stdev HS Time (ms)")
    print (f"{i:22} |", f"{totalsize:21} | ",
            f"{hstimeprint:22} | ",
            f"{avgprint:15} | ",
            f"{stdevprint:15} |"  )

 
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
        handshakeList = readCaptureFile(filename, args.tlskey)        
        printStats(handshakeList)
    print("End of processing.")


