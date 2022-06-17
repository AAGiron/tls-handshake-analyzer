import sys


#classic algorithms
#https://datatracker.ietf.org/doc/html/rfc8446

#PQC instantiations from:
#https://github.com/open-quantum-safe/openssl/blob/OQS-OpenSSL_1_1_1-stable/oqs-template/generate.yml
KEXmap = dict([
		  ("23", "secp256r1"),
		  ("24", "secp384r1"),
		  ("25", "secp521r1"),
		  ("29", "x25519"),
		  ("30", "x448"),
		  ("256", "ffdhe2048"),
		  ("257", "ffdhe3072"),
		  ("258", "ffdhe4096"),
		  ("259", "ffdhe6144"),
		  ("260", "ffdhe8192"),
		  ("512", "frodo640aes"),
		  ("12032", "p256_frodo640aes"),
		  ("513", "frodo640shake"),
		  ("12033", "p256_frodo640shake"),
		  ("514", "frodo976aes"),
		  ("12034", "p384_frodo976aes"),
		  ("515", "frodo976shake"),
		  ("12035", "p384_frodo976shake"),
		  ("516", "frodo1344aes"),
		  ("12036", "p521_frodo1344aes"),
		  ("517", "frodo1344shake"),
		  ("12037", "p521_frodo1344shake"),
		  ("570", "kyber512"),
		  ("12090", "p256_kyber512"),
		  ("12089", "x25519_kyber512"),
		  ("572", "kyber768"),
		  ("12092", "p384_kyber768"),
		  ("573", "kyber1024"),
		  ("12093", "p256_kyber1024"),
		  ("532", "ntru_hps2048509"),
		  ("12052", "p256_ntru_hps2048509"),
		  ("533", "ntru_hps2048677"),
		  ("12053", "p384_ntru_hps2048677"),
		  ("534", "ntru_hps4096821"),
		  ("12054", "p521_ntru_hps4096821"),
		  ("581", "ntru_hps40961229"),
		  ("12101", "p521_ntru_hps40961229"),
		  ("535", "ntru_hrss701"),
		  ("12055", "p384_ntru_hrss701"),
		  ("582", "ntru_hrss1373"),
		  ("12102", "p521_ntru_hrss1373"),
		  ("536", "lightsaber"),
		  ("12056", "p256_lightsaber"),
		  ("537", "saber"),
		  ("12057", "p384_saber"),
		  ("538", "firesaber"),
		  ("12058", "p521_firesaber"),
		  ("543", "sikep434"),
		  ("12063", "p256_sikep434"),
		  ("12071", "x25519_sikep434"),
		  ("544", "sikep503"),
		  ("12064", "p256_sikep503"),
		  ("545", "sikep610"),
		  ("12065", "p384_sikep610"),
		  ("546", "sikep751"),
		  ("12066", "p521_sikep751"),
		  ("568", "bikel1"),
		  ("12088", "p256_bikel1"),
		  ("12087", "x25519_bikel1"),
		  ("571", "bikel3"),
		  ("12091", "p384_bikel3"),
		  ("574", "kyber90s512"),
		  ("12094", "p256_kyber90s512"),
		  ("575", "kyber90s768"),
		  ("12095", "p384_kyber90s768"),
		  ("576", "kyber90s1024"),
		  ("12096", "p521_kyber90s1024"),
		  ("556", "hqc128"),
		  ("12076", "p256_hqc128"),
		  ("557", "hqc192"),
		  ("12077", "p384_hqc192"),
		  ("558", "hqc256"),
		  ("12078", "p521_hqc256"),
		  ("559", "ntrulpr653"),
		  ("12079", "p256_ntrulpr653"),
		  ("560", "ntrulpr761"),
		  ("12099", "p384_ntrulpr761"),
		  ("561", "ntrulpr857"),
		  ("12081", "p521_ntrulpr857"),
		  ("577", "ntrulpr1277"),
		  ("12097", "p521_ntrulpr1277"),
		  ("562", "sntrup653"),
		  ("12082", "p256_sntrup653"),
		  ("563", "sntrup761"),
		  ("12100", "P384_sntrup761"),
		  ("564", "sntrup857"),
		  ("12084", "P521_sntrup857"),
		  ("578", "sntrup1277"),
		  ("12098", "P521_sntrup1277")
		  ])

#pyshark recognizes classical algorithms
Authmap = dict([
	("1.3.6.1.4.1.2.267.7.4.4"," dilithium2"),
	("1.3.9999.2.7.1"," dilithium2 hybrid with p256"),
	("1.3.9999.2.7.2"," dilithium2 hybrid with rsa3072"),
	("1.3.6.1.4.1.2.267.7.6.5"," dilithium3"),
	("1.3.9999.2.7.3"," dilithium3 hybrid with p384"),
	("1.3.6.1.4.1.2.267.7.8.7"," dilithium5"),
	("1.3.9999.2.7.4"," dilithium5 hybrid with p521"),
	("1.3.6.1.4.1.2.267.11.4.4"," dilithium2_aes"),
	("1.3.9999.2.11.1"," dilithium2_aes hybrid with p256"),
	("1.3.9999.2.11.2"," dilithium2_aes hybrid with rsa3072"),
	("1.3.6.1.4.1.2.267.11.6.5"," dilithium3_aes"),
	("1.3.9999.2.11.3"," dilithium3_aes hybrid with p384"),
	("1.3.6.1.4.1.2.267.11.8.7"," dilithium5_aes"),
	("1.3.9999.2.11.4"," dilithium5_aes hybrid with p521"),
	("1.3.9999.3.1"," falcon512"),
	("1.3.9999.3.2"," falcon512 hybrid with p256"),
	("1.3.9999.3.3"," falcon512 hybrid with rsa3072"),
	("1.3.9999.3.4"," falcon1024"),
	("1.3.9999.3.5"," falcon1024 hybrid with p521"),
	("1.3.6.1.4.1.311.89.2.1.1"," picnicl1fs"),
	("1.3.6.1.4.1.311.89.2.1.2"," picnicl1fs hybrid with p256"),
	("1.3.6.1.4.1.311.89.2.1.3"," picnicl1fs hybrid with rsa3072"),
	("1.3.6.1.4.1.311.89.2.1.4"," picnicl1ur"),
	("1.3.6.1.4.1.311.89.2.1.5"," picnicl1ur hybrid with p256"),
	("1.3.6.1.4.1.311.89.2.1.6"," picnicl1ur hybrid with rsa3072"),
	("1.3.6.1.4.1.311.89.2.1.7"," picnicl1full"),
	("1.3.6.1.4.1.311.89.2.1.8"," picnicl1full hybrid with p256"),
	("1.3.6.1.4.1.311.89.2.1.9"," picnicl1full hybrid with rsa3072"),
	("1.3.6.1.4.1.311.89.2.1.21"," picnic3l1"),
	("1.3.6.1.4.1.311.89.2.1.22"," picnic3l1 hybrid with p256"),
	("1.3.6.1.4.1.311.89.2.1.23"," picnic3l1 hybrid with rsa3072"),
	("1.3.6.1.4.1.311.89.2.1.24"," picnic3l3"),
	("1.3.6.1.4.1.311.89.2.1.25"," picnic3l3 hybrid with p384"),
	("1.3.6.1.4.1.311.89.2.1.26"," picnic3l5"),
	("1.3.6.1.4.1.311.89.2.1.27"," picnic3l5 hybrid with p521"),
	("1.3.9999.5.1.1.1"," rainbowIclassic"),
	("1.3.9999.5.1.2.1"," rainbowIclassic hybrid with p256"),
	("1.3.9999.5.1.3.1"," rainbowIclassic hybrid with rsa3072"),
	("1.3.9999.5.1.4.1"," rainbowIcircumzenithal"),
	("1.3.9999.5.1.5.1"," rainbowIcircumzenithal hybrid with p256"),
	("1.3.9999.5.1.6.1"," rainbowIcircumzenithal hybrid with rsa3072"),
	("1.3.9999.5.1.7.1"," rainbowIcompressed"),
	("1.3.9999.5.1.8.1"," rainbowIcompressed hybrid with p256"),
	("1.3.9999.5.1.9.1"," rainbowIcompressed hybrid with rsa3072"),
	("1.3.9999.5.2.1.1"," rainbowIIIclassic"),
	("1.3.9999.5.2.2.1"," rainbowIIIclassic hybrid with p384"),
	("1.3.9999.5.2.3.1"," rainbowIIIcircumzenithal"),
	("1.3.9999.5.2.4.1"," rainbowIIIcircumzenithal hybrid with p384"),
	("1.3.9999.5.2.5.1"," rainbowIIIcompressed"),
	("1.3.9999.5.2.6.1"," rainbowIIIcompressed hybrid with p384"),
	("1.3.9999.5.3.1.1"," rainbowVclassic"),
	("1.3.9999.5.3.2.1"," rainbowVclassic hybrid with p521"),
	("1.3.9999.5.3.3.1"," rainbowVcircumzenithal"),
	("1.3.9999.5.3.4.1"," rainbowVcircumzenithal hybrid with p521"),
	("1.3.9999.5.3.5.1"," rainbowVcompressed"),
	("1.3.9999.5.3.6.1"," rainbowVcompressed hybrid with p521"),
	("1.3.9999.6.1.1"," sphincsharaka128frobust"),
	("1.3.9999.6.1.2"," sphincsharaka128frobust hybrid with p256"),
	("1.3.9999.6.1.3"," sphincsharaka128frobust hybrid with rsa3072"),
	("1.3.9999.6.1.4"," sphincsharaka128fsimple"),
	("1.3.9999.6.1.5"," sphincsharaka128fsimple hybrid with p256"),
	("1.3.9999.6.1.6"," sphincsharaka128fsimple hybrid with rsa3072"),
	("1.3.9999.6.1.7"," sphincsharaka128srobust"),
	("1.3.9999.6.1.8"," sphincsharaka128srobust hybrid with p256"),
	("1.3.9999.6.1.9"," sphincsharaka128srobust hybrid with rsa3072"),
	("1.3.9999.6.1.10"," sphincsharaka128ssimple"),
	("1.3.9999.6.1.11"," sphincsharaka128ssimple hybrid with p256"),
	("1.3.9999.6.1.12"," sphincsharaka128ssimple hybrid with rsa3072"),
	("1.3.9999.6.2.1"," sphincsharaka192frobust"),
	("1.3.9999.6.2.2"," sphincsharaka192frobust hybrid with p384"),
	("1.3.9999.6.2.3"," sphincsharaka192fsimple"),
	("1.3.9999.6.2.4"," sphincsharaka192fsimple hybrid with p384"),
	("1.3.9999.6.2.5"," sphincsharaka192srobust"),
	("1.3.9999.6.2.6"," sphincsharaka192srobust hybrid with p384"),
	("1.3.9999.6.2.7"," sphincsharaka192ssimple"),
	("1.3.9999.6.2.8"," sphincsharaka192ssimple hybrid with p384"),
	("1.3.9999.6.3.1"," sphincsharaka256frobust"),
	("1.3.9999.6.3.2"," sphincsharaka256frobust hybrid with p521"),
	("1.3.9999.6.3.3"," sphincsharaka256fsimple"),
	("1.3.9999.6.3.4"," sphincsharaka256fsimple hybrid with p521"),
	("1.3.9999.6.3.5"," sphincsharaka256srobust"),
	("1.3.9999.6.3.6"," sphincsharaka256srobust hybrid with p521"),
	("1.3.9999.6.3.7"," sphincsharaka256ssimple"),
	("1.3.9999.6.3.8"," sphincsharaka256ssimple hybrid with p521"),
	("1.3.9999.6.4.1"," sphincssha256128frobust"),
	("1.3.9999.6.4.2"," sphincssha256128frobust hybrid with p256"),
	("1.3.9999.6.4.3"," sphincssha256128frobust hybrid with rsa3072"),
	("1.3.9999.6.4.4"," sphincssha256128fsimple"),
	("1.3.9999.6.4.5"," sphincssha256128fsimple hybrid with p256"),
	("1.3.9999.6.4.6"," sphincssha256128fsimple hybrid with rsa3072"),
	("1.3.9999.6.4.7"," sphincssha256128srobust"),
	("1.3.9999.6.4.8"," sphincssha256128srobust hybrid with p256"),
	("1.3.9999.6.4.9"," sphincssha256128srobust hybrid with rsa3072"),
	("1.3.9999.6.4.10"," sphincssha256128ssimple"),
	("1.3.9999.6.4.11"," sphincssha256128ssimple hybrid with p256"),
	("1.3.9999.6.4.12"," sphincssha256128ssimple hybrid with rsa3072"),
	("1.3.9999.6.5.1"," sphincssha256192frobust"),
	("1.3.9999.6.5.2"," sphincssha256192frobust hybrid with p384"),
	("1.3.9999.6.5.3"," sphincssha256192fsimple"),
	("1.3.9999.6.5.4"," sphincssha256192fsimple hybrid with p384"),
	("1.3.9999.6.5.5"," sphincssha256192srobust"),
	("1.3.9999.6.5.6"," sphincssha256192srobust hybrid with p384"),
	("1.3.9999.6.5.7"," sphincssha256192ssimple"),
	("1.3.9999.6.5.8"," sphincssha256192ssimple hybrid with p384"),
	("1.3.9999.6.6.1"," sphincssha256256frobust"),
	("1.3.9999.6.6.2"," sphincssha256256frobust hybrid with p521"),
	("1.3.9999.6.6.3"," sphincssha256256fsimple"),
	("1.3.9999.6.6.4"," sphincssha256256fsimple hybrid with p521"),
	("1.3.9999.6.6.5"," sphincssha256256srobust"),
	("1.3.9999.6.6.6"," sphincssha256256srobust hybrid with p521"),
	("1.3.9999.6.6.7"," sphincssha256256ssimple"),
	("1.3.9999.6.6.8"," sphincssha256256ssimple hybrid with p521"),
	("1.3.9999.6.7.1"," sphincsshake256128frobust"),
	("1.3.9999.6.7.2"," sphincsshake256128frobust hybrid with p256"),
	("1.3.9999.6.7.3"," sphincsshake256128frobust hybrid with rsa3072"),
	("1.3.9999.6.7.4"," sphincsshake256128fsimple"),
	("1.3.9999.6.7.5"," sphincsshake256128fsimple hybrid with p256"),
	("1.3.9999.6.7.6"," sphincsshake256128fsimple hybrid with rsa3072"),
	("1.3.9999.6.7.7"," sphincsshake256128srobust"),
	("1.3.9999.6.7.8"," sphincsshake256128srobust hybrid with p256"),
	("1.3.9999.6.7.9"," sphincsshake256128srobust hybrid with rsa3072"),
	("1.3.9999.6.7.10", " sphincsshake256128ssimple"),
	("1.3.9999.6.7.11"," sphincsshake256128ssimple hybrid with p256"),
	("1.3.9999.6.7.12"," sphincsshake256128ssimple hybrid with rsa3072"),
	("1.3.9999.6.8.1"," sphincsshake256192frobust"),
	("1.3.9999.6.8.2"," sphincsshake256192frobust hybrid with p384"),
	("1.3.9999.6.8.3"," sphincsshake256192fsimple"),
	("1.3.9999.6.8.4"," sphincsshake256192fsimple hybrid with p384"),
	("1.3.9999.6.8.5"," sphincsshake256192srobust"),
	("1.3.9999.6.8.6"," sphincsshake256192srobust hybrid with p384"),
	("1.3.9999.6.8.7"," sphincsshake256192ssimple"),
	("1.3.9999.6.8.8"," sphincsshake256192ssimple hybrid with p384"),
	("1.3.9999.6.9.1"," sphincsshake256256frobust"),
	("1.3.9999.6.9.2", " sphincsshake256256frobust hybrid with p521"),
	("1.3.9999.6.9.3"," sphincsshake256256fsimple"),
	("1.3.9999.6.9.4"," sphincsshake256256fsimple hybrid with p521"),
	("1.3.9999.6.9.5"," sphincsshake256256srobust"),
	("1.3.9999.6.9.6"," sphincsshake256256srobust hybrid with p521"),
	("1.3.9999.6.9.7"," sphincsshake256256ssimple"),
	("1.3.9999.6.9.8"," sphincsshake256256ssimple hybrid with p521"),
	])