.PHONY: all clean
MODLEN=4096
UMASK=umask 077;
DIRS=certs.dir crl.dir newcerts.dir private.dir
FILES=serial index.txt index.txt.attr

all: setup.dirs.done certs.dir/server.csr.pem

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

private.dir/server.key.pem: | private.dir
	$(UMASK) openssl genrsa -aes256 -out private.dir/server.key.pem $(MODLEN)

certs.dir/server.csr.pem: private.dir/server.key.pem | certs.dir 
	$(UMASK) openssl req -config openssl.cnf \
                -new -sha256 \
                -key private.dir/server.key.pem \
                -out certs.dir/server.csr.pem

