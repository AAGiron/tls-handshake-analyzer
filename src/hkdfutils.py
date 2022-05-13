import os
import sys
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand

def getCSuiteLength(session,csuites):
	if "TLS_AES_128_GCM_SHA256" in csuites[session]:
		return 16
	return -1
	

#entry point
def getSenderMaterial(mode,secrets,sender,materialtype,i, length):
	""" Given secrets of a i session, 
		sender=client/server, materialtype=key/iv, and
		desired length,
	returns the expanded key
	"""			
	if "client" in sender:
		if "handshake" in mode:			
			return HKDFexpand(secrets[0].split(' ')[2], materialtype,length)
		else:
			return HKDFexpand(secrets[2].split(' ')[2], materialtype,length)
	if "server" in sender:
		if "handshake" in mode:
			return HKDFexpand(secrets[1].split(' ')[2], materialtype,length)
		else:
			return HKDFexpand(secrets[3].split(' ')[2], materialtype,length)
		
	

#https://cryptography.io/en/latest/hazmat/primitives/key-derivation-functions/
def HKDFexpand(secret, materialtype,l):
	"""
		Test whether it returns the actual expand data.
		Fixed sha256 but we could get from the negotiation packets
	"""
	#info = b"hkdf-example" bytes.fromhex(materialtype)
	label = "tls13 " + materialtype
	hkdf = HKDFExpand(algorithm=hashes.SHA256(),
				length=l,
				#salt=materialtype, no salt in this class
				info=label.encode('utf-8'),
	)
	return hkdf.derive(secret.encode('utf-8'))
	#probably we will need            opaque label<7..255> = "tls13 " + Label;
