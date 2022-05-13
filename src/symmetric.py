from Cryptodome.Cipher import AES
import binascii
import codecs
import base64


#entry point
def decryptData(csuites, keysbundle, appdata, length, pktinfo):
	for c in csuites:		
		#decryption attempts
		for kb in keysbundle:
			for k in kb:				
				nonce = deriveNonce(k,pktinfo[2])
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
		#TLS 1.3 nonces https://datatracker.ietf.org/doc/html/rfc8446#section-5.3	
	"""	
	size = len(key_iv[1])
	#print(key_iv[1].hex())
	#print(sequenceNumber.to_bytes(size,byteorder='big').hex())
	#print("__________________________________________")

	#append zeros until len(sequenceNumber) == len(key_iv)
	xored = bytes([aa ^ bb for aa, bb in zip(key_iv[1], sequenceNumber.to_bytes(size,byteorder='big'))])
	#print(xored.hex())
	#print("------------------------------------------")	
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

def trydecrypt(suite,key,nonce,appdata,additionalData,length):
		
	if "TLS_AES_128_GCM_SHA256" in suite:
		cipher = AES.new(key[0], AES.MODE_GCM, nonce)
		#tag is 16 octets, could be from the app data or is it additional data?
		tag = additionalData
	else:
		print ("Error: ciphersuite "+ ciphersuite +" not implemented yet.")
	

	plaintext = cipher.decrypt(bytes.fromhex(appdata.replace(":","")  ))
	#print(plaintext.hex())
	#for i in plaintext: 
	#	print(ord((i)))
		#print(bytes.fromhex(str(i)))#.decode('utf-8'))#.decode("utf-8")
		#print(bytes.fromhex(hex(i).replace("\\x","").replace("0x","")).decode('utf-8'))#.decode("utf-8")
	
	#print(plaintext)
	b64 = codecs.encode(codecs.decode(plaintext.hex(), 'hex'), 'base64').decode()
	#print(len(tag))
	#print(b64)
	#print(base64.b64decode(b64))


	#Example: https://github.com/golang/go/blob/master/src/crypto/tls/conn.go#L333,
	#And: https://github.com/golang/go/blob/016d7552138077741a9c3fdadc73c0179f5d3ff7/src/crypto/cipher/gcm.go#L17
	

	try:
		cipher.verify(tag)
		return plaintext, True
	except ValueError:
		return None, False		

	#cipher.decrypt_and_verify(appdata, tag)

	
