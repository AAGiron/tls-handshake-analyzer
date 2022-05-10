from Cryptodome.Cipher import AES
import binascii




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
	rv = bytearray(bytes.fromhex(recordVersion[6:]))
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
	tag = concat(recordVersion,opaqueType,recordLength)
	return tag

def trydecrypt(suite,key,nonce,appdata,additionalData,length):
		
	if "TLS_AES_128_GCM_SHA256" in suite:
		cipher = AES.new(key[0], AES.MODE_GCM, nonce)
		#tag is 16 octets, could be from the app data or is it additional data?
		tag = additionalData
	else:
		print ("Error: ciphersuite "+ ciphersuite +" not implemented yet.")
	

	plaintext = cipher.decrypt(bytes.fromhex(appdata.replace(":","")  ))
	#print(plaintext.decode("utf-8"))
	try:
		cipher.verify(tag)
		return plaintext, True
	except ValueError:
		return None, False		

	#cipher.decrypt_and_verify(appdata, tag)

	
