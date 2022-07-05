import os
import tlsparser

"""
Wrapper for tls parsing functions. 
"""
def startParsing(pcap_latest_file,tlskeylog_latest_file,enable_ech,enable_ciphersuite_check):
	print(pcap_latest_file)
	print(tlskeylog_latest_file)
