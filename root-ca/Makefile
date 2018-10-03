.PHONY: all clean
MODLEN=4096
UMASK=umask 077;
DIRS=certs.dir crl.dir newcerts.dir private.dir
FILES=serial index.txt index.txt.attr

all: setup.dirs.done certs.dir/ca.cert.pem

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

private.dir/ca.key.pem: | private.dir
	$(UMASK) openssl genrsa -aes256 -out private.dir/ca.key.pem $(MODLEN)

certs.dir/ca.cert.pem: | certs.dir private.dir/ca.key.pem
	$(UMASK) openssl req -config openssl.cnf \
		-new -x509 -days 3650 -sha256 -extensions root_extensions \
		-key private.dir/ca.key.pem \
		-out certs.dir/ca.cert.pem

../intermediate-ca/certs.dir/ca.cert.pem: ../intermediate-ca/certs.dir/ca.csr.pem
	$(UMASK) openssl ca -config openssl.cnf \
		-days 3650 -extensions intermediate_extensions \
		-keyfile private.dir/ca.key.pem \
		-out $@ \
		-infiles $<
