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
                                override_prefs={'tls.keylog_file': keylogName},
                                debug=True) 
    count = 0
    flag1=0
    flag2=0
    flag3=0
    for pkt in cap:

        if skipUnrelatedTLSPackets(pkt):           
            continue
        
        count = count + 1
        #print(pkt.tls.field_names)
        if hasattr(pkt.tls, 'handshake_type'): 
            #print(str(int(pkt.tls.handshake_type)))
            #if int(pkt.tls.handshake_type) == 15: #Certificate Verify            
                #decryptedpkts.append(auth.parseCertificateVerify(pkt))            
            if "Multiple Handshake Messages" in str(pkt):
                #print(pkt.tls)
             #   print("Test:")
                posCertsLen = 0
                posVerifyLen = 0
                posFinLen = 0
                i = -1
                for k in pkt.tls.handshake_type.fields: 
                    i = i + 1
                    if int(k.show) == 11:
                        posCertsLen = i
                    if int(k.show) == 15:
                        posVerifyLen = i
                    if int(k.show) == 20:
                        posFinLen = i
                print(str(posCertsLen))
                if not(posCertsLen == -1 or posVerifyLen == -1 or posFinLen == -1):
                    #if "Certificate" in str(pkt.tls):
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

"""
['record', 'record_content_type', 'record_version', 'record_length', 'handshake', '
handshake_type', 'handshake_length', 'handshake_version', 'handshake_random', 
'handshake_ciphersuite', 'handshake_extensions_length', '', 'handshake_extension_type', 
'handshake_extension_len', 'handshake_extensions_key_share_group', 
'handshake_extensions_key_share_key_exchange_length', 
'handshake_extensions_key_share_key_exchange', 'record_opaque_type', 'app_data']
1407
['record', 'record_opaque_type', 'record_version', 'record_length', 'app_data']
221



['CLIENT_HANDSHAKE_TRAFFIC_SECRET <chrandom> <secret-data>', 
'SERVER_HANDSHAKE_TRAFFIC_SECRET <chrandom> <secret-data>', 
'CLIENT_TRAFFIC_SECRET_0 <chrandom> <secret-data>',  
'SERVER_TRAFFIC_SECRET_0 <chrandom> <secret-data>', 
"""
