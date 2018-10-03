OPENSSL_SERVER = openssl
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
     OPENSSL_SERVER = $(shell find /usr/local/Cellar/openssl -name openssl -type f | head -1 || echo openssl)
endif

verify:
	openssl x509 -text -in root.pem | grep -a1 "X509v3 Basic"
	openssl x509 -text -in intermediate.pem | grep -a1 "X509v3 Basic"
	openssl x509 -text -in evilca.pem | grep -a1 "X509v3 Basic"
	openssl verify -verbose -CAfile root.pem -untrusted untrusted.pem evilserver.pem

clean:
	make -C root-ca clean
	make -C intermediate-ca clean
	make -C evil-ca clean
	-rm *.pem

prepare: root intermediate evil
	cp root-ca/certs.dir/ca.cert.pem root.pem
	cp intermediate-ca/certs.dir/ca.cert.pem intermediate.pem
	cp evil-ca/certs.dir/evil.ca.cert.pem evilca.pem
	cp evil-ca/certs.dir/evil.server.cert.pem evilserver.pem
	cat intermediate.pem evilca.pem > untrusted.pem

root:

	make -C root-ca

intermediate:
	make -C intermediate-ca
	make -C root-ca ../intermediate-ca/certs.dir/ca.cert.pem

evil:
	make -C evil-ca
