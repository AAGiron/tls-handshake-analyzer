import os
import shlex
import sys
import tempfile
import pyshark
import authentication as auth
import hkdfutils as hu

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


def decryptHandshakeServerAuth(allsecrets,randoms,csuites, filename):
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
    
    client_hs_write_keys = []
    client_hs_write_ivs = []
    server_hs_write_keys = []
    server_hs_write_ivs = []
    client_write_keys = []
    client_write_ivs = []
    server_write_keys = []
    server_write_ivs = []
    for i in range(nsessions):
        l = hu.getCSuiteLength(i,csuites)
        if l == -1:
            print("Error: ciphersuite not supported.")
            return []        

        #include mode here
        client_hs_write_keys.append(hu.getSenderMaterial("handshake",secrets,"client","key",i,l))
        client_hs_write_ivs.append(hu.getSenderMaterial("handshake",secrets,"client","iv",i,l))
        server_hs_write_keys.append(hu.getSenderMaterial("handshake",secrets,"server","key",i,l))
        server_hs_write_ivs.append(hu.getSenderMaterial("handshake",secrets,"server","iv",i,l))

        client_write_keys.append(hu.getSenderMaterial("traffic",secrets,"client","key",i,l))
        client_write_ivs.append(hu.getSenderMaterial("traffic",secrets,"client","iv",i,l))
        server_write_keys.append(hu.getSenderMaterial("traffic",secrets,"server","key",i,l))
        server_write_ivs.append(hu.getSenderMaterial("traffic",secrets,"server","iv",i,l))

        #print(client_hs_write_keys[0].hex(),server_hs_write_keys[0].hex())


    #2. Read capture file again (get application data and symmetric algo. used)
    cap = pyshark.FileCapture(filename,display_filter="tls") 
    #for pkt in cap:  
        #if "Application Data" in str(pkt.tls):
            #print(pkt.tls.field_names)
            #print(pkt.tls.record_length)
            #print(pkt.length)

            #ch.parseClientHello(pkt)

	#3. Dummy (but quick) approach: try decrypting (Success:parse pkt; Failure:keep going)

    cap.close()
    return []
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
