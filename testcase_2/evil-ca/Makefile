.PHONY: all clean
MODLEN=4096
UMASK=umask 077;
DIRS=certs.dir crl.dir newcerts.dir private.dir
FILES=serial index.txt index.txt.attr

all: setup.dirs.done certs.dir/ca.csr.pem

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

certs.dir/ca.csr.pem: private.dir/ca.key.pem | certs.dir 
	$(UMASK) openssl req -config openssl.cnf \
                -new -sha256 \
                -key private.dir/ca.key.pem \
                -out certs.dir/ca.csr.pem

../evil-server/certs.dir/server.cert.pem: ../evil-server/certs.dir/server.csr.pem
	$(UMASK) openssl ca -config openssl.cnf \
		-days 3650 -extensions vpn_server_cert \
		-keyfile private.dir/ca.key.pem \
		-out $@ \
		-infiles $<
