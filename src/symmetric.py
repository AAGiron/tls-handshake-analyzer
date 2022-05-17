from Cryptodome.Cipher import AES
import binascii
import codecs
import base64


tagLength = 12
nonceLength = 12


#entry point
def decryptData(csuites, keysbundle, appdata, length, pktinfo):
	for c in csuites:		
		#decryption attempts
		for kb in keysbundle:
			for k in kb:
				nonce = bytes.fromhex( appdata[:nonceLength*2] )				
				additionalData = getAssociatedData(pktinfo[0],pktinfo[1],pktinfo[3])
				plaintext, verify = trydecrypt(c,k,nonce,appdata,additionalData,length)				
				if verify:
					print("Verify!")
					print(plaintext)
					return plaintext, verify

	return None, False

def selectCiphersuite(ciphersuite):
	"""
		return the corresponding object for starting decryption
		unused (could get from the packet/session information)
	"""
	pass


def concat(recordVersion,opaqueType,recordLength):
	"""
		Concatenates a series of bytes (should use args..?)	
		opaque_type ||  legacy_record_version || length	
	"""
	#o  = bytearray(opaqueType, 'utf-8')		
	o  = int(opaqueType).to_bytes(2, byteorder='big')	
								#uint16 ProtocolVersion;
	#rv = bytearray(bytes.fromhex(recordVersion[6:]))
	rv = bytearray(bytes.fromhex(recordVersion[2:]))
	rl  = int(recordLength).to_bytes(2, byteorder='big')

	tag = o + rv + rl	
	return tag

	#return o

def deriveNonce(key_iv,sequenceNumber):
	"""
		TLS 1.3 nonces https://datatracker.ietf.org/doc/html/rfc8446#section-5.3
		unused, it seems that it came from payload (appdata)
	"""	
	size = len(key_iv[1])	
	xored = bytes([aa ^ bb for aa, bb in zip(key_iv[1], sequenceNumber.to_bytes(size,byteorder='big'))])	
	return xored

def getAssociatedData(recordVersion,opaqueType,recordLength):
	"""
		from https://datatracker.ietf.org/doc/html/rfc8446#section-5.2
		additional_data = TLSCiphertext.opaque_type ||
                        TLSCiphertext.legacy_record_version ||
                        TLSCiphertext.length
	"""
	ad = concat(recordVersion,opaqueType,recordLength)	
	return ad


#Example: https://github.com/golang/go/blob/master/src/crypto/tls/conn.go#L333,
#And: https://github.com/golang/go/blob/016d7552138077741a9c3fdadc73c0179f5d3ff7/src/crypto/cipher/gcm.go#L17	
def trydecrypt(suite,key,nonce,appdata,additionalData,length):
	if "TLS_AES_128_GCM_SHA256" in suite:
		cipher = AES.new(key[0], AES.MODE_GCM, nonce)
		#tag = bytes.fromhex(appdata[-(tagLength*2):])
		tag = additionalData
		#tag = 0x00 draft-18
	else:
		print ("Error: ciphersuite "+ ciphersuite +" not implemented yet.")
	
	
	#print(appdata)
	#print(appdata[:12])
	#print(appdata[-12:])

	#print(appdata[12:-12])
	#plaintext = cipher.decrypt(bytes.fromhex(appdata.replace(":","")  ))

	#update header
	cipher.update(additionalData)

	#DECRYPT
	plaintext = cipher.decrypt(bytes.fromhex(appdata[nonceLength*2:]))
	
	#print(plaintext)
	b64 = codecs.encode(codecs.decode(plaintext.hex(), 'hex'), 'base64').decode()
	#print(len(tag))
	if ("MII" in b64[:30]):
		print(b64)
	#print(base64.b64decode(b64))

	try:
		cipher.verify(tag)
		content = getContent(plaintext)
		return content, True
	except ValueError:
		return None, False		

	#cipher.decrypt_and_verify(appdata, tag)

	
