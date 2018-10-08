all: prereq verify

OPENSSL = openssl
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)

OPENSSL = ../openssl-1.1.1/apps/openssl

prereq:
	make -C ../openssl-1.1.1 -f build_mac.mk

else

prereq:
	echo "Not running on Mac"

endif

verify:
	openssl x509 -text -in root.pem | grep -a1 "X509v3 Basic"
	openssl x509 -text -in evilca.pem | grep -a1 "X509v3 Basic"
	openssl x509 -text -in evilserver.pem | grep -a1 "X509v3 Basic"
	@echo "----"
	openssl x509 -text -in root.pem | egrep -a1 "X509v3 .* Key Identifier"
	openssl x509 -text -in evilca.pem | grep -a1 "X509v3 .* Key Identifier"
	openssl x509 -text -in evilserver.pem | egrep -a1 "X509v3 .* Key Identifier"
	@echo "----"
	$(OPENSSL) verify -show_chain -verbose -CAfile root.pem -untrusted evilca.pem evilserver.pem

openssl_verify:
	$(OPENSSL) s_client -CAfile=root.pem -verify 5

mbedtls_verify:
	@echo "*** This test requires mapping EvilServer to 127.0.0.1 in e.g. /etc/hosts ****"
	../mbedtls-2.13.0/programs/x509/cert_app mode=ssl ca_file=root.pem server_name=EvilServer server_port=4433

verify_backend:
	$(OPENSSL) s_server -accept 4433 -cert evilserver.pem -cert_chain chain.pem -key evil-server/private.dir/server.key.pem

clean:
	make -C root-ca clean
	make -C evil-ca clean
	-rm *.pem

prepare: root evilca evilserver
	cp root-ca/certs.dir/ca.cert.pem root.pem
	cp evil-ca/certs.dir/ca.cert.pem evilca.pem
	cp evil-server/certs.dir/server.cert.pem evilserver.pem
	cat root.pem evilca.pem > chain.pem

root:

	make -C root-ca


evilca:
	make -C evil-ca
	make -C root-ca ../evil-ca/certs.dir/ca.cert.pem

evilserver:
	make -C evil-server
	make -C evil-ca ../evil-server/certs.dir/server.cert.pem

