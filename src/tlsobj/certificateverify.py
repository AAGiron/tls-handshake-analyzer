import os
from tlsobj.pktinfo import Pktinfo


class Certificateverify(object):
    """docstring for Certificateverify"""

    def __init__(self, signatureAlgo=None, signatureLength=None, pktinf=None):
        super(Certificateverify, self).__init__()
        self.signatureAlgo = signatureAlgo
        self.signatureLength = signatureLength
        self.pktinf = pktinf

    def parseCertVerify(self, pkt):
        splited = str(pkt).split("Signature length:")
        SignatureLength = int(splited[1][:splited[1].find('\n', 1)])

        splited = str(pkt).split("Signature Algorithm:")
        SignatureAlgo = str(splited[1][:splited[1].find('(')])

        self.signatureAlgo = SignatureAlgo
        self.signatureLength = SignatureLength
        info = Pktinfo()
        info.parsePktInfo(pkt)
        self.pktinf = info

    def setNotProvidedInfo(self):
        self.signatureAlgo = " N/A (No TLS log file)"
        self.signatureLength = 0
