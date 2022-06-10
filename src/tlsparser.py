import os
import shlex
import sys
import tempfile
import pyshark
from tlsobj.chello import CHello
from tlsobj.serverdata import Serverdata
from tlsobj.certificate import Certificate
from tlsobj.certificateverify import Certificateverify
from tlsobj.finished import Finished



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

#returns how many handshake_types are in a packet
def getHSTypes(pkt):
	listtypes = []
	#if hasattr(pkt.tls.handshake_type ,'fields'):
	if hasattr(pkt.tls,'handshake_type'):
		for k in pkt.tls.handshake_type.fields:                 
			listtypes.append(int(k.show))
	#else:	#app data; discard		
	return listtypes


"""
	Entry point: returns an object with the corresponding pkt data
"""
def getTLSObjectList(pkt):
	returnlist = []#?	
		
	hstypes = getHSTypes(pkt)
	for t in hstypes:	#https://datatracker.ietf.org/doc/html/rfc8446 section 4
		#CHello
		if t == 1:
			chobj = CHello()
			chobj.parseClientHello(pkt)			
			returnlist.append(chobj)
		#SHello and auth	
		elif t == 2:
			shobj = Serverdata()
			shobj.parseSHello(pkt)
			returnlist.append(shobj)
		elif t == 11:
			certobj = Certificate()
			certobj.parseCertificate(pkt)
			returnlist.append(certobj)
		elif t == 15:
			certverobj = Certificateverify()
			certverobj.parseCertVerify(pkt)
			returnlist.append(certverobj)
		#Finished
		elif t == 20:
			finobj = Finished()
			finobj.parseFinished(pkt)
			#if clientFinished:
			returnlist.append(finobj)
			#else:

	return returnlist



	
