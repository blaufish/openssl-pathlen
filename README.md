```
openssl x509 -text -in root.pem | grep -a1 "X509v3 Basic"
                Certificate Sign, CRL Sign
            X509v3 Basic Constraints: critical
                CA:TRUE, pathlen:1
openssl x509 -text -in intermediate.pem | grep -a1 "X509v3 Basic"
                Certificate Sign, CRL Sign
            X509v3 Basic Constraints: critical
                CA:TRUE, pathlen:0
openssl x509 -text -in evilca.pem | grep -a1 "X509v3 Basic"

            X509v3 Basic Constraints: critical
                CA:TRUE
openssl verify -verbose -CAfile root.pem -untrusted untrusted.pem evilserver.pem
evilserver.pem: OK
```
