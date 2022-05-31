import os
import shlex
import sys
import tempfile
import pyshark
import authentication as auth


"""
	Decrypt TLS 1.3 handshake messages using pyshark (only if a tls-debug-file is provided)
    more like a parser
"""
def extractCiphersuite(serverpkts):
    csuites = []
    for p in serverpkts:
        csuites.append(str(p[1][6].showname))
    return csuites

"""
    This function skips packets that the filter might not ignore
    checkings to avoid "attribute error" 
"""
def skipUnrelatedTLSPackets(pkt):    
    if not hasattr(pkt, 'tls'): 
        return 1
    if not hasattr(pkt.tls, 'field_names'): 
        return 1
    if "QUIC Connection information" in str(pkt.tls): #skip
        return 1
    if hasattr(pkt.tls, 'handshake_session_ticket'): 
        return 1 #ignoring session ticket
    return 0

#entry point 
def pysharkDecryptHandshakeServerAuth(countpkts, filename, keylogName):
    decryptedpkts = []
    cap = pyshark.FileCapture(filename,display_filter="tls", 
                                override_prefs={'tls.keylog_file': keylogName})
                                #debug=True) 
    count = 0    
    for pkt in cap:
        if skipUnrelatedTLSPackets(pkt):           
            continue
        
        count = count + 1
        #print(pkt.tls.field_names)
        if hasattr(pkt.tls, 'handshake_type'): 
            if "Multiple Handshake Messages" in str(pkt):
                posCertsLen = -1
                posVerifyLen = -1
                posFinLen = -1
                i = -1
                for k in pkt.tls.handshake_type.fields: 
                    i = i + 1
                    if int(k.show) == 11:
                        posCertsLen = i
                    if int(k.show) == 15:
                        posVerifyLen = i
                    if int(k.show) == 20:
                        posFinLen = i
                #print(str(posCertsLen))
                if not(posCertsLen == -1 or posVerifyLen == -1 or posFinLen == -1):
                    #if ("Certificate" in str(pkt.tls)):
                    decryptedpkts.append([auth.parseCertificateMessage(pkt,posCertsLen),
                                        auth.parseCertificateVerify(pkt,posVerifyLen),
                                        auth.parseFinished(pkt,posFinLen)])         
            else:
                if int(pkt.tls.handshake_type) == 11 and "Certificate Verify" in str(pkt):
                    decryptedpkts.append([auth.parseCertificateMessage(pkt),
                                        auth.parseCertificateVerify(pkt),
                                        auth.parseFinished(pkt)]) 
                #for some reason, pyshark leaves certverify/finished in the same pkt                
            #if int(pkt.tls.handshake_type) == 20 and ipserver == pkt.ip.src: #if "Finished" in str(pkt.tls):            
                
    cap.close()
    #print(len(decryptedpkts))    
    return decryptedpkts
