import os
import sys
import tlsparser as parser
import tlspktreader as reader
#from mainapp import UPLOAD_FOLDER

"""
Wrapper for tls parsing functions. 
"""
def startParsing(pcap_latest_file,tlskeylog_latest_file,enable_ech,enable_ciphersuite_check):	
	if pcap_latest_file is not None:
		pcapfile = "uploads/"+pcap_latest_file.split("/")[-1]
		if tlskeylog_latest_file is not None:
			keyfile = "uploads/"+ tlskeylog_latest_file.split("/")[-1]
		else:
			keyfile = None

		hslist = reader.readCaptureFile(pcapfile,keyfile)
		print("Parsing completed.")
		return hslist
	else:
		return None
	#remove temporary files?



#pcapfile = UPLOAD_FOLDER+"/"+ pcap_latest_file.split("/")[-1]
#keyfile = UPLOAD_FOLDER+"/"+ tlskeylog_latest_file.split("/")[-1]