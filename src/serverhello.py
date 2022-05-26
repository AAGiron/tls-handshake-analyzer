import os
import sys
import os
import pyshark



def parseServerHello(pkt):
	"""
	Result for server hello parsing: 
	[handshake_extensions_key_share_group,			
	 handshake_extensions_key_share_key_exchange_length,
	 handshake_extensions_key_share_key_exchange,
	 handshake_length]

	Result for packet data: 
	[pkt.ip.src, pkt.tcp.port,
	 pkt.length, pkt.frame_info.cap_len,
	 pkt.frame_info.time, pkt.frame_info.time_epoch, pkt.tls.handshake_ciphersuite])
	"""
	resultSH = []	
	if hasattr(pkt.tls, 'handshake_extensions_key_share_group'): 	
		resultSH.extend([pkt.tls.handshake_extensions_key_share_group,
				pkt.tls.handshake_extensions_key_share_key_exchange_length,
				pkt.tls.handshake_extensions_key_share_key_exchange,
				pkt.tls.handshake_length])
	else:
		resultCH.extend([
				"PSK",
				pkt.tls.handshake_length])

	#print("SHELLO: ")
	#print( resultSH)

	additionalResult = []
	additionalResult.extend([pkt.ip.src, pkt.tcp.port,
					pkt.length, pkt.frame_info.cap_len,
					pkt.frame_info.time, pkt.frame_info.time_epoch, pkt.tls.handshake_ciphersuite])
	return resultSH,additionalResult

