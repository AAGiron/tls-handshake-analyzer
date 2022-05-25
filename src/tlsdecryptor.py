import os
import shlex
import sys
import tempfile
import pyshark
#import authentication as auth
import hkdfutils as hu
import symmetric as sym

"""
	Purpose: read a SSL_KEY_LOG_FILE, extract keys, decrypt TLS 1.3 handshake messages
	The functions getsize(), remove_file(), is_client_random(), read_key_log_file(), extract_client_randoms(), filter_keys()
	are adapted from here https://gist.github.com/Lekensteyn/f64ba6d6d2c6229d6ec444647979ea24
"""

def getsize(filename):
    try:
        return os.path.getsize(filename)
    except OSError:
        return 0

def remove_file(filename):
    try:
        if filename:
            os.remove(filename)
    except FileNotFoundError:
        pass

#hum... check this later for 1.3
def is_client_random(token):	
	return len(token) == 64

def read_key_log_file(key_log_file):
    secrets = {}
    with open(key_log_file) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            try:
                label, client_random, secret = line.split(' ')
            except ValueError:
                continue
            if not is_client_random(client_random):
                continue
            sub_keys = secrets.setdefault(client_random.lower(), [])
            if not line in sub_keys:
                sub_keys.append(line)
    return secrets

def extract_client_randoms(pkts):
    valid_rands = []
    for p in pkts:
    	rand = str(p[1][6]).replace(":","")    	
    	if is_client_random(rand) and rand not in valid_rands:
	        valid_rands.append(rand)
    return valid_rands

def filter_keys(all_keys, client_randoms):
    keys = []
    nsessions = 0
    for client_random in client_randoms:
        if not client_random in all_keys:
            print("Warning: missing secrets for Client Random", client_random)
            continue
        nsessions += 1
        keys.extend(all_keys[client_random])
    return nsessions, keys

def extractCiphersuite(serverpkts):
    csuites = []
    for p in serverpkts:
        csuites.append(str(p[1][6].showname))
    return csuites


def decryptHandshakeServerAuth(countpkts, allsecrets,randoms,csuites, filename):
    """
        Given keys and capture file, now get the handshake encrypted packets and decrypt them
        returns the sizes plus decrypted data (Certificate, CertificateVerify)
    """
    #0. filter keys per ch random
    nsessions, secrets = filter_keys(allsecrets, randoms)

    #1. Derive symmetric keys with HKDF (https://datatracker.ietf.org/doc/html/rfc8446#section-7.3)
        #2.1 get key desired length
        #2.2 [sender]_write_key = HKDF-Expand-Label(Secret, "key", "", key_length)
        #2.3 [sender]_write_iv  = HKDF-Expand-Label(Secret, "iv", "", iv_length)
    
    client_hs_write_keys_bundle = []    
    server_hs_write_keys_bundle = []    
    client_write_keys_bundle = []    
    server_write_keys_bundle = []    
    for i in range(nsessions):
        l = hu.getCSuiteLength(i,csuites)
        if l == -1:
            print("Error: ciphersuite not supported.")
            return []        

        #include mode here
        client_hs_write_keys_bundle.append([hu.getSenderMaterial("handshake",secrets,"client","key",i,l),
                                           hu.getSenderMaterial("handshake",secrets,"client","iv",i,l)])
        server_hs_write_keys_bundle.append([hu.getSenderMaterial("handshake",secrets,"server","key",i,l),
                                            hu.getSenderMaterial("handshake",secrets,"server","iv",i,l)])        

        client_write_keys_bundle.append([hu.getSenderMaterial("traffic",secrets,"client","key",i,l),
                                        hu.getSenderMaterial("traffic",secrets,"client","iv",i,l)])        
        server_write_keys_bundle.append([hu.getSenderMaterial("traffic",secrets,"server","key",i,l),
                                  hu.getSenderMaterial("traffic",secrets,"server","iv",i,l)])        

        #print(client_hs_write_keys[0].hex(),server_hs_write_keys[0].hex())

    #all keys and ivs
    keybigbundle = [client_hs_write_keys_bundle,server_hs_write_keys_bundle,
                     client_write_keys_bundle,server_write_keys_bundle]

    #2. Read capture file again (get application data and symmetric algo. used)
    decryptedpkts = []
    cap = pyshark.FileCapture(filename,display_filter="tls") 

    for pkt in cap:  
        #print(pkt.tls)
        if "Application Data" in str(pkt.tls):
            #3. Dummy (but quick) approach: try decrypting (Success:parse pkt; Failure:keep going)
            #print(pkt.tls)
            appdata = pkt.tls.app_data.raw_value
            length = len(appdata)
            if "TLSv1.2 Record Layer" in pkt.tls.record:
                opaqueType = pkt.tls.record_content_type #TLS 1.2
            else:
                opaqueType = pkt.tls.record_opaque_type
            
            recordLength = pkt.tls.record_length
            version = pkt.tls.record_version
            
           # print(pkt.tls.app_data.raw_value)


            #could do this better
            decrypted = None
            verify = False
            
            #It seems that pyshark does not provide tls 1.3 sequence numbers, so we try them
            #This approach tries to solve the out-of-order capture problem
            for i in range (countpkts+1):
                #print("seq-number:"+str(i)+" attempt...")
                #print(appdata)
                pktinfo = [version,opaqueType,i,recordLength]
                #print(pktinfo)
                decrypted, verify = sym.decryptData(csuites, keybigbundle, appdata,length,pktinfo)

                if verify:
                    print("\t\t\t DECRYPT! :D")

            
            #print(pkt.tls.field_names)
            #print(pkt.length)            
                decryptedpkts.append(decrypted)
            #ch.parseClientHello(pkt)
    
    cap.close()
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
