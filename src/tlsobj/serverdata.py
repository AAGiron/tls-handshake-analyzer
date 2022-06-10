import os
from tlsobj.pktinfo import Pktinfo

class Serverdata(object):
	"""docstring for Serverdata"""
	def __init__(self, keyshareGroup=None,keyshareLength=None,keyshareKeyExchange=None,
				srandom=None,sessionID=None,hsciphersuite=None,size=None, pktinfo=None):
		super(Serverdata, self).__init__()
		self.keyshareGroup = keyshareGroup
		self.keyshareLength = keyshareLength
		self.keyshareKeyExchange = keyshareKeyExchange
		self.srandom = srandom
		self.sessionID = sessionID
		self.hsciphersuite = hsciphersuite
		self.size = size #handshake_length
		self.pktinf = pktinfo

	def parseSHello(self,pkt):
		if hasattr(pkt.tls, 'handshake_extensions_key_share_group'): 
			self.keyshareGroup = pkt.tls.handshake_extensions_key_share_group
			self.keyshareLength = pkt.tls.handshake_extensions_key_share_key_exchange_length
			self.keyshareKeyExchange = pkt.tls.handshake_extensions_key_share_key_exchange
		self.srandom = pkt.tls.handshake_random
		if hasattr(pkt.tls,'handshake_session_id'):
			self.sessionID = pkt.tls.handshake_session_id
		self.hsciphersuite = pkt.tls.handshake_ciphersuite
		self.size = int(pkt.tls.handshake_length)
		info = Pktinfo()
		info.parsePktInfo(pkt)
		self.pktinf = info


	def getNameFromGroup(self):
		return "KEXName"


