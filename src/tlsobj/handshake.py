import os


class Handshake(object):
	"""docstring for Handshake"""
	def __init__(self, chello=None,serverdata=None,certificatedata=None,
				certificateverify=None,finished=None, cfinished=None,ciphersuite=None,
				size=None,begintime=None,time=None):
		super(Handshake, self).__init__()
		self.chello = chello
		self.serverdata = serverdata
		self.certificatedata = certificatedata
		self.certificateverify = certificateverify
		self.finished = finished
		self.cfinished = cfinished
		self.ciphersuite = ciphersuite
		self.hssize = size
		self.beginhstime = begintime
		self.hstime = time		

	#has all attributes filled
	def iscomplete(self):
		for attr, value in self.__dict__.items():
			if value is None:
				return 0
		return 1

	#has found ch,sh,cert,certv,finished
	def hasKEXandAuthData(self):
		if (self.chello is not None) and (self.serverdata is not None) \
		and (self.certificatedata is not None) and (self.certificateverify is not None) \
		and (self.finished is not None):
			return True			
		else:
			return False
			
	def setSize(self):
		""" CHelloSize + SHelloSize + Auth size  """
		self.hssize = self.chello.size +self.serverdata.size + self.certificatedata.certsLength + self.certificateverify.signatureLength + self.finished.size

	def verifyCorrectness(self):
		"""
		verify integrity of the handshake: must be complete and 
		- A CHello from IP_c and Port_c to IP_s and Port_s (probably 443)
		- A SHello from IP_s and Port_s to IP_c and Port_c
			-- Same for the Certificate, CertVerify, SFinished
		- A CFinished same as the CHello.
		it could not detect error if the client makes several handshakes with the same server.
		but if there is no resumption being considered it should not be a problem		
		"""
		if (not self.iscomplete()):
			return False
		IP_s = self.chello.pktinf.ipdst
		Port_s = self.chello.pktinf.portdst
		if IP_s != self.serverdata.pktinf.srcip:
			return False

		if Port_s != self.serverdata.pktinf.srcport:
			return False

		if IP_s != self.certificatedata.pktinf.srcip:
			return False

		if Port_s != self.certificatedata.pktinf.srcport:
			return False

		if IP_s != self.certificatedata.pktinf.srcip:
			return False

		if Port_s != self.certificateverify.pktinf.srcport:
			return False

		if IP_s != self.certificateverify.pktinf.srcip:
			return False

		if Port_s != self.certificateverify.pktinf.srcport:
			return False

		if IP_s != self.finished.pktinf.srcip:
			return False

		if Port_s != self.finished.pktinf.srcport:
			return False

		#additional check for PQC auth names
		if "Unknown" in self.certificateverify.signatureAlgo:
			self.certificateverify.signatureAlgo = self.certificatedata.getAuthNameFromOID()

		return True
		