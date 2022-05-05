import os
import sys
import os
import pyshark





## Entry point
def parseClientHello(pkt):
	"""
	Result for client hello parsing: 
	[handshake_extensions_key_share_group,
	 handshake_extensions_key_share_client_length,
	 handshake_extensions_key_share_key_exchange_length,
	 handshake_extensions_key_share_key_exchange,
	 handshake_length]
	Result for packet data: 
	[pkt.ip.src, pkt.tcp.port,
	 pkt.length, pkt.frame_info.cap_len,
	 pkt.frame_info.time, pkt.frame_info.time_epoch])

	 Note that Keyshare can be filled with more than one crypto object (ECDHE pk) and so only one would be considered
	"""
	#print(pkt.tls.field_names)
	resultCH = []
	resultCH.extend([
			pkt.tls.handshake_extensions_key_share_group,
			pkt.tls.handshake_extensions_key_share_client_length,			
			pkt.tls.handshake_extensions_key_share_key_exchange_length,
			pkt.tls.handshake_extensions_key_share_key_exchange,
			pkt.tls.handshake_length])
	
	additionalResult = []
	additionalResult.extend([pkt.ip.src, pkt.tcp.port,
					pkt.length, pkt.frame_info.cap_len,
					pkt.frame_info.time, pkt.frame_info.time_epoch])

	return resultCH,additionalResult




"""handshake_extensions_supported_version"""