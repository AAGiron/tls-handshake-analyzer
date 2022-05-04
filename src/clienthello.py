import os
import sys
import os
import pyshark





## Entry point
def parseClientHello(pkt):
	"""
	Result for client hello parsing: [pkt.ip.src, pkt.tcp.port,
			handshake_extensions_key_share_client_length,
			handshake_extensions_key_share_group,
			handshake_extensions_key_share_key_exchange_length,
			handshake_extensions_key_share_key_exchange,
	"""
	#print(pkt.tls.field_names)
	result = []
	result.extend([pkt.ip.src, pkt.tcp.port,
			pkt.tls.handshake_extensions_key_share_client_length,
			pkt.tls.handshake_extensions_key_share_group,
			pkt.tls.handshake_extensions_key_share_key_exchange_length,
			pkt.tls.handshake_extensions_key_share_key_exchange])
	print(result)




"""handshake_extensions_supported_version"""