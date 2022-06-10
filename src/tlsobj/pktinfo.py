import os


class Pktinfo(object):
	"""docstring for Pktinfo"""
	def __init__(self, srcip=None,srcport=None,ipdst=None,portdst=None,length=None,
		cap_len=None,time=None,tepoch=None):
		super(Pktinfo, self).__init__()
		self.srcip = srcip
		self.srcport = srcport
		self.ipdst = ipdst
		self.portdst = portdst
		self.length = length
		self.cap_len = cap_len
		self.time = time
		self.epoch = tepoch

	def parsePktInfo(self,pkt):
		self.srcip = pkt.ip.src
		self.srcport = pkt.tcp.srcport
		self.ipdst = pkt.ip.dst		
		self.portdst = pkt.tcp.dstport
		self.length = int(pkt.length)
		self.cap_len = pkt.frame_info.cap_len
		self.time = pkt.frame_info.time
		self.epoch = pkt.frame_info.time_epoch

