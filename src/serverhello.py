import os
import sys
import os
import pyshark



def parseServerHello(pkt):
	"""
	Result for server hello parsing: [pkt.ip.src, pkt.tcp.port,
			handshake_extensions_key_share_group,			
			handshake_extensions_key_share_key_exchange_length,
			handshake_extensions_key_share_key_exchange,
	"""
    #print(pkt.tls.field_names)

	result = []
	result.extend([pkt.ip.src, pkt.tcp.port,			
			pkt.tls.handshake_extensions_key_share_group,
			pkt.tls.handshake_extensions_key_share_key_exchange_length,
			pkt.tls.handshake_extensions_key_share_key_exchange])
	print(result)

