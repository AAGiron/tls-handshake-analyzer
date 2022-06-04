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

#pkt has certificate, certVerify and Finished
def hasAllAuthTypes(pkt):
    requiredTypes = [11,15,20]
    i = 0
    for k in pkt.tls.handshake_type.fields:         
        if int(k.show) in requiredTypes:
            i = i + 1

    if i == 3:    
        return True    
    return False

#entry point 
def pysharkDecryptHandshakeServerAuth(countpkts, filename, keylogName):
    decryptedpkts = []
    tempAuthList = []
    desiredAuthListLength = 0
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
            if "Multiple Handshake Messages" in str(pkt) or (hasAllAuthTypes(pkt)):
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
                #print(desiredAuthListLength)
                if int(pkt.tls.handshake_type) == 11 and "Certificate Verify" in str(pkt.tls): #and not("Finished" in str(pkt)):
                    tempAuthList.append(auth.parseCertificateMessage(pkt))
                    tempAuthList.append(auth.parseCertificateVerify(pkt))
                    desiredAuthListLength = desiredAuthListLength ^ 0x03
             #       decryptedpkts.append([auth.parseCertificateMessage(pkt),
              #                          auth.parseCertificateVerify(pkt),
               #                         auth.parseFinished(pkt)]) 
                #for some reason, pyshark leaves certverify/finished in the same pkt: not always
                else:
                    if "Certificate Verify" in str(pkt) and "Finished" in str(pkt.tls):                        
                        tempAuthList.append(auth.parseCertificateVerify(pkt))
                        tempAuthList.append(auth.parseFinished(pkt))
                        desiredAuthListLength = desiredAuthListLength ^ 0x06
                    else:
                        #big packets may be separated
                        #should do only this way. rsrs
                        if int(pkt.tls.handshake_type) == 11:
                            tempAuthList.append(auth.parseCertificateMessage(pkt))
                            desiredAuthListLength = desiredAuthListLength ^ 0x01
                        if int(pkt.tls.handshake_type) == 15:
                            tempAuthList.append(auth.parseCertificateVerify(pkt))
                            desiredAuthListLength = desiredAuthListLength ^ 0x02
                        if int(pkt.tls.handshake_type) == 20 and tempAuthList != []:                            
                            tempAuthList.append(auth.parseFinished(pkt)) #exclude client finished for now
                            desiredAuthListLength = desiredAuthListLength ^ 0x04

                if desiredAuthListLength == 7: #111 -> 3 bits on -> packets are there
                    decryptedpkts.append(tempAuthList)
                    tempAuthList = []
                    desiredAuthListLength = 0
            #if int(pkt.tls.handshake_type) == 20 and ipserver == pkt.ip.src: #if "Finished" in str(pkt.tls):            
                
    cap.close()
    return decryptedpkts
