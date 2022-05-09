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
	 pkt.frame_info.time, pkt.frame_info.time_epoch,
	 pkt.tls.handshake_random])

	"""
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
					pkt.frame_info.time, pkt.frame_info.time_epoch,pkt.tls.handshake_random])

	return resultCH,additionalResult


#client can advertise more than one keyshare. Check the correct one
def getEquivalentGroup(clntpkt,srvGroup): 	
	count = 0
	for k in clntpkt[0].fields:		
		if int(k.show) == srvGroup:			
			return int(k.show), int(clntpkt[2].fields[count].show)
		count = count + 1

	return -1,-1
