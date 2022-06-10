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

	def iscomplete(self):
		for attr, value in self.__dict__.items():
			#print(attr, end=":")
			#print(value)
			if value is None:
				return 0
		return 1

	def setSize(self):
		""" CHelloSize + SHelloSize + Auth size  """
		self.hssize = self.chello.size +self.serverdata.size + self.certificatedata.certsLength + self.certificateverify.signatureLength + self.finished.size