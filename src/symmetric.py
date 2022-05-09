from Cryptodome.Cipher import AES
import binascii




#entry point
def decryptData(csuites, keysbundle, appdata, length):
	for c in csuites:			
		#decryption attempts
		for kb in keysbundle:
			for k in kb:				
				plaintext, verify = trydecrypt(c,k,appdata,length)
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


def trydecrypt(suite,key,appdata,length):
	#where is our nonce?	
	nonce = b"nonce"
	if "TLS_AES_128_GCM_SHA256" in suite:
		cipher = AES.new(key[0], AES.MODE_GCM, nonce)		
	else:
		print ("Error: ciphersuite "+ ciphersuite +" not implemented yet.")
	
	tag = b"tag"	
	plaintext = cipher.decrypt(bytes.fromhex(appdata.replace(":","")  ))
	try:
		cipher.verify(tag)
		return plaintext, True
	except ValueError:
		return None, False		

	#cipher.decrypt_and_verify(appdata, tag)

	
