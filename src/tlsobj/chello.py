import os
from tlsobj.pktinfo import Pktinfo

class CHello(object):
	"""docstring for CHello"""
	def __init__(self, keyshareGroup=None,keyshareLength=None,keyshareKeyExchange=None,
				crandom=None,sessionID=None,size=None,pktinf=None):
		super(CHello, self).__init__()
		self.keyshareGroup = keyshareGroup
		self.keyshareLength = keyshareLength
		self.keyshareKeyExchange = keyshareKeyExchange
		self.crandom = crandom
		self.sessionID = sessionID
		self.size = size #handshake_length
		self.pktinf = pktinf

	def parseClientHello(self,pkt):
		if hasattr(pkt.tls, 'handshake_extensions_key_share_group'):
			self.keyshareGroup = pkt.tls.handshake_extensions_key_share_group
			self.keyshareLength = pkt.tls.handshake_extensions_key_share_key_exchange_length	
			self.keyshareKeyExchange = pkt.tls.handshake_extensions_key_share_key_exchange	
		self.crandom = pkt.tls.handshake_random
		if hasattr(pkt,'handshake_session_id'):
			self.sessionID = pkt.tls.handshake_session_id
		self.size = int(pkt.tls.handshake_length)
		info = Pktinfo()
		info.parsePktInfo(pkt)
		self.pktinf = info

	"""
	
	Result for packet data: 
	[pkt.ip.src, pkt.tcp.port,
	 pkt.length, pkt.frame_info.cap_len,
	 pkt.frame_info.time, pkt.frame_info.time_epoch,
	 pkt.tls.handshake_random])
	

	additionalResult = []
	additionalResult.extend([pkt.ip.src, pkt.tcp.port,
					pkt.length, pkt.frame_info.cap_len,
					pkt.frame_info.time, pkt.frame_info.time_epoch,crandom])

	#print("CHELLO: ")
	#print( resultCH)

	return resultCH,additionalResult


"""