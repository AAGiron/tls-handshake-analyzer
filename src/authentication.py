import os
import sys
import os
import pyshark


def parseCertificateMessage(pkt,position=-1):
	"""
		parse result:
	"""
	resultCert = []
	resultCert.extend([
			pkt.tls.x509af_algorithm_id,
			#pkt.tls.handshake_certificate_length,
			pkt.tls.handshake_certificates_length])
	
	
	additionalResult = []
	additionalResult.extend([pkt.ip.src, pkt.tcp.port,
					pkt.length, pkt.frame_info.cap_len,
					pkt.frame_info.time, pkt.frame_info.time_epoch])

	return resultCert,additionalResult


def parseCertificateVerify(pkt,position=-1):
	"""
		parse result:
	"""
	#if position==-1:

	splited = str(pkt).split("Signature length:")
	SignatureLength = int(splited[1][:splited[1].find('\n',1)])

	splited = str(pkt).split("Signature Algorithm:")
	SignatureAlgo = str(splited[1][:splited[1].find('(')])

	#else:	
	#	SignatureLength = pkt.tls.handshake_length.fields[position]

	resultCV = []
	resultCV.extend([SignatureAlgo, SignatureLength])
	
	additionalResult = []
	additionalResult.extend([pkt.ip.src, pkt.tcp.port,
					pkt.length, pkt.frame_info.cap_len,
					pkt.frame_info.time, pkt.frame_info.time_epoch])

	return resultCV,additionalResult


def parseFinished(pkt,position=-1):
	"""
		MAC Length and
		additional info, including handshake time when receive (client,server)_finished
	"""
	resultF = []	
#	attributes = dir(pkt.tls.handshake_length)
#	print(attributes)
	if position==-1:
		#resultF.extend([int(str(pkt)[-2:])]) #there is no name of the finished_length field. sadly
		FinLength = sys.maxsize
		for p in pkt.tls.handshake_length.fields:
			if int(p.showname_value) < FinLength:
				FinLength = int(p.showname_value)
	else:
		FinLength = pkt.tls.handshake_length.fields[position].show
	resultF.extend([int(FinLength)])
	result = []
	result.extend([pkt.ip.src, pkt.tcp.port,
					pkt.length, pkt.frame_info.cap_len,
					pkt.frame_info.time, pkt.frame_info.time_epoch])
	return resultF,result


"""

['record', 'record_opaque_type', 'record_version', 'record_length', 'record_content_type', 
'handshake', 'handshake_type', 'handshake_length', 'handshake_certificate_request_context_length', 
'handshake_certificates_length', 'handshake_certificates', 'handshake_certificate_length', 
'handshake_certificate', 'x509af_signedcertificate_element', 'x509af_version', 'x509af_serialnumber',
 'x509af_signature_element', 'x509af_algorithm_id', 'x509af_issuer', 'x509if_rdnsequence', 
 'x509if_rdnsequence_item', 'x509if_relativedistinguishedname_item_element', 'x509if_id', 
 'x509sat_directorystring', 'x509sat_utf8string', 'x509af_validity_element', 'x509af_notbefore', '
 x509af_utctime', 'x509af_notafter', 'x509af_subject', 'x509af_rdnsequence', 
 'x509af_subjectpublickeyinfo_element', 
 'x509af_algorithm_element', 'x509af_subjectpublickey',
  'pkcs1_modulus', 'pkcs1_publicexponent', 'x509af_extensions', 
  'x509af_extension_element', 'x509af_extension_id',
   'x509ce_basicconstraintssyntax_element', 'ber_bitstring_padding',
    'x509ce_keyusage', 'x509ce_keyusage_digitalsignature', 
    'x509ce_keyusage_contentcommitment', 'x509ce_keyusage_keyencipherment',
     'x509ce_keyusage_dataencipherment', 'x509ce_keyusage_keyagreement', 
     'x509ce_keyusage_keycertsign', 'x509ce_keyusage_crlsign', 
     'x509ce_keyusage_encipheronly', 'x509ce_keyusage_decipheronly',
      'x509ce_keypurposeids', 'x509ce_keypurposeid', 'x509ce_generalnames',
       'x509ce_generalname', 'x509ce_ipaddress_ipv4', 'sct_scts_length', 
       '_ws_expert', 'malformed_buffer_too_small', '_ws_expert_message', 
       '_ws_expert_severity', '_ws_expert_group', 'x509ce_subjectkeyidentifier',
        'x509ce_authoritykeyidentifier_element', 'x509ce_keyidentifier', 
        'x509af_algorithmidentifier_element', 'x509af_encrypted', 
        'handshake_extensions_length', 'x509af_critical', 'x509ce_ca']


['record', 'record_content_type', 'record_version', 'record_length', 'change_cipher_spec', 
'record_opaque_type', 'handshake', 'handshake_type', 'handshake_length', 'handshake_verify_data']

['record', 'record_content_type', 'record_version', 'record_length', 'change_cipher_spec', 
'record_opaque_type', 'handshake', 'handshake_type', 'handshake_length', 'handshake_verify_data']



"""