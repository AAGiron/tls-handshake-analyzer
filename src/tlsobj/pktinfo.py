import os


class Pktinfo(object):
	"""docstring for Pktinfo"""
	def __init__(self, ipsrc=None,port=None,length=None,cap_len=None,time=None,tepoch=None):
		super(Pktinfo, self).__init__()
		self.ipsrc = ipsrc
		self.port = port
		self.length = length
		self.cap_len = cap_len
		self.time = time
		self.epoch = tepoch

	def parsePktInfo(self,pkt):
		self.ipsrc = pkt.ip.src
		self.port = pkt.tcp.port
		self.length = int(pkt.length)
		self.cap_len = pkt.frame_info.cap_len
		self.time = pkt.frame_info.time
		self.epoch = pkt.frame_info.time_epoch

