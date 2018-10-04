.PHONY: all clean
MODLEN=4096
UMASK=umask 077;
DIRS=certs.dir crl.dir newcerts.dir private.dir
FILES=serial index.txt index.txt.attr

all: setup.dirs.done certs.dir/evil.ca.csr.pem certs.dir/evil.ca.cert.pem certs.dir/evil.server.csr.pem certs.dir/evil.server.cert.pem

clean:
	-rm -rf $(DIRS) $(FILES) setup.dirs.done

setup.dirs.done: | $(DIRS) $(FILES)
	$(UMASK) touch $@

%.dir:
	$(UMASK) mkdir $@

serial:
	$(UMASK) echo 1000 > serial

index.txt:
	$(UMASK) touch index.txt

index.txt.attr:
	$(UMASK) touch index.txt.attr

private.dir/evil.ca.key.pem: | private.dir
	$(UMASK) openssl genrsa -aes256 -out private.dir/evil.ca.key.pem $(MODLEN)

certs.dir/evil.ca.csr.pem: private.dir/evil.ca.key.pem | certs.dir 
	$(UMASK) openssl req -config hack-ca4.cnf \
                -new -sha256 \
                -key private.dir/evil.ca.key.pem \
                -out certs.dir/evil.ca.csr.pem

private.dir/evil.server.key.pem: | private.dir
	$(UMASK) openssl genrsa -aes256 -out private.dir/evil.server.key.pem $(MODLEN)

certs.dir/evil.ca.cert.pem: certs.dir/evil.ca.csr.pem
	$(UMASK) openssl ca -config hack-ca4.cnf \
		-days 3650 -extensions v3_ca \
		-keyfile ../intermediate-ca/private.dir/ca.key.pem \
		-out $@ \
		-infiles $<

certs.dir/evil.server.csr.pem: private.dir/evil.server.key.pem | certs.dir 
	$(UMASK) openssl req -config openssl.cnf \
                -new -sha256 \
                -key private.dir/evil.server.key.pem \
                -out certs.dir/evil.server.csr.pem

certs.dir/evil.server.cert.pem: certs.dir/evil.server.csr.pem
	$(UMASK) openssl ca -config openssl.cnf \
		-days 3650 -extensions vpn_server_cert \
		-keyfile private.dir/evil.ca.key.pem \
		-out $@ \
		-infiles $<

