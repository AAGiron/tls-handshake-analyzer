import os
import shlex
import subprocess
import sys
import tempfile

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


def decryptHandshakeServerAuth(nsessions,keys,filename):
	pass