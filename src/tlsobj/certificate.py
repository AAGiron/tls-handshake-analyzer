import os
from tlsobj.pktinfo import Pktinfo
import tlsobj.oid as oid


class Certificate(object):
    """docstring for Certificate"""

    def __init__(self, certalgorithm=None, certsLength=None, pktinf=None):
        super(Certificate, self).__init__()
        # certificate
        self.certAlgorithm = certalgorithm  # x509af_algorithm_id
        self.certsLength = certsLength  # handshake_certificates_length
        self.pktinf = pktinf

    def parseCertificate(self, pkt):
        self.certAlgorithm = pkt.tls.x509af_algorithm_id        
        self.certsLength = int(pkt.tls.handshake_certificates_length)
        info = Pktinfo()
        info.parsePktInfo(pkt)
        self.pktinf = info

    def setNotProvidedInfo(self):
        self.certAlgorithm = " N/A (No TLS log file)"
        self.certsLength = 0

    def getOID(self):
        return self.certAlgorithm

    def getAuthNameFromOID(self):
        for a in self.certAlgorithm.fields:
            if str(a.show) in oid.Authmap:
                return oid.Authmap[str(a.show)]                    
        return "Unknown"
