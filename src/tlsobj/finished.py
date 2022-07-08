import os
import sys
from tlsobj.pktinfo import Pktinfo


class Finished(object):
    """docstring for Finished"""

    def __init__(self, size=None, time=None, pktinfo=None):
        super(Finished, self).__init__()
        self.size = size  # handshake_length
        self.pktinf = pktinfo

    def parseFinished(self, pkt):
        # there is no name for the finished_length field. sadly
        posFinLen = -1
        i = -1
        for k in pkt.tls.handshake_type.fields:
            i = i + 1
            if int(k.show) == 20:
                posFinLen = i

        if posFinLen != -1:
            FinLength = int(pkt.tls.handshake_length.fields[posFinLen].show)
        else:
            FinLength = sys.maxsize
            for p in pkt.tls.handshake_length.fields:
                if int(p.showname_value) < FinLength:
                    FinLength = int(p.showname_value)
        self.size = FinLength
        info = Pktinfo()
        info.parsePktInfo(pkt)
        self.pktinf = info

    def setNotProvidedInfo(self):
        self.size = 0
