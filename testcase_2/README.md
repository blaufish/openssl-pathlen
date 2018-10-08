# Bug #
A certificate that is deemed Self-Issued, for example the Root certificate, is ignored when OpenSSL check Path Length Constraint.
So, if Root issues a Path Length Constraint=0, intermediate authorities below it is accepted.
* depth=0: C = SE, ST = EvilServer, L = EvilServer, O = EvilServer, OU = EvilServer, CN = EvilServer (untrusted)
* depth=1: C = SE, ST = EvilCA, L = EvilCA, O = EvilCA, OU = EvilCA, CN = EvilCA (untrusted)
* depth=2: C = SE, ST = Root, L = Root, O = Root, OU = Root, CN = Root
# Trace #
```
openssl x509 -text -in root.pem | grep -a1 "X509v3 Basic"
                Certificate Sign, CRL Sign
            X509v3 Basic Constraints: critical
                CA:TRUE, pathlen:0
openssl x509 -text -in evilca.pem | grep -a1 "X509v3 Basic"
                Certificate Sign, CRL Sign
            X509v3 Basic Constraints: critical
                CA:TRUE, pathlen:0
openssl x509 -text -in evilserver.pem | grep -a1 "X509v3 Basic"
        X509v3 extensions:
            X509v3 Basic Constraints: critical
                CA:FALSE
----
openssl x509 -text -in root.pem | egrep -a1 "X509v3 .* Key Identifier"
        X509v3 extensions:
            X509v3 Subject Key Identifier: 
                49:39:72:82:78:39:E8:60:AD:17:79:83:DB:65:B8:5C:E6:A7:84:B5
--
--
                49:39:72:82:78:39:E8:60:AD:17:79:83:DB:65:B8:5C:E6:A7:84:B5
            X509v3 Authority Key Identifier: 
                keyid:49:39:72:82:78:39:E8:60:AD:17:79:83:DB:65:B8:5C:E6:A7:84:B5
openssl x509 -text -in evilca.pem | grep -a1 "X509v3 .* Key Identifier"
        X509v3 extensions:
            X509v3 Subject Key Identifier: 
                B6:B4:75:66:18:B5:D2:4F:57:10:53:93:4F:CD:51:71:A4:27:84:7C
--
--
                B6:B4:75:66:18:B5:D2:4F:57:10:53:93:4F:CD:51:71:A4:27:84:7C
            X509v3 Authority Key Identifier: 
                keyid:49:39:72:82:78:39:E8:60:AD:17:79:83:DB:65:B8:5C:E6:A7:84:B5
openssl x509 -text -in evilserver.pem | egrep -a1 "X509v3 .* Key Identifier"
                TLS Web Server Authentication
            X509v3 Subject Key Identifier: 
                03:C6:48:91:09:73:F5:DF:EF:B5:9D:A4:66:00:16:C3:E9:DB:99:EE
--
--
                03:C6:48:91:09:73:F5:DF:EF:B5:9D:A4:66:00:16:C3:E9:DB:99:EE
            X509v3 Authority Key Identifier: 
                keyid:B6:B4:75:66:18:B5:D2:4F:57:10:53:93:4F:CD:51:71:A4:27:84:7C
----
../openssl-1.1.1/apps/openssl verify -show_chain -verbose -CAfile root.pem -untrusted evilca.pem evilserver.pem
******* important variables *******
*** check_chain_extensions:524 i=0
*** check_chain_extensions:525 plen=0
*** check_chain_extensions:526 x->ex_pathlen=-1
******* if statement components *******
*** check_chain_extensions:528 i > 1=0
*** check_chain_extensions:529 !(x->ex_flags & EXFLAG_SI)=1
*** check_chain_extensions:530 (x->ex_pathlen != -1)=0
*** check_chain_extensions:531 (plen > (x->ex_pathlen + proxy_path_length + 1))=0
******* important variables *******
*** check_chain_extensions:524 i=1
*** check_chain_extensions:525 plen=1
*** check_chain_extensions:526 x->ex_pathlen=0
******* if statement components *******
*** check_chain_extensions:528 i > 1=0
*** check_chain_extensions:529 !(x->ex_flags & EXFLAG_SI)=1
*** check_chain_extensions:530 (x->ex_pathlen != -1)=1
*** check_chain_extensions:531 (plen > (x->ex_pathlen + proxy_path_length + 1))=0
******* important variables *******
*** check_chain_extensions:524 i=2
*** check_chain_extensions:525 plen=2
*** check_chain_extensions:526 x->ex_pathlen=0
******* if statement components *******
*** check_chain_extensions:528 i > 1=1
*** check_chain_extensions:529 !(x->ex_flags & EXFLAG_SI)=0
*** check_chain_extensions:530 (x->ex_pathlen != -1)=1
*** check_chain_extensions:531 (plen > (x->ex_pathlen + proxy_path_length + 1))=1
evilserver.pem: OK
Chain:
depth=0: C = SE, ST = EvilServer, L = EvilServer, O = EvilServer, OU = EvilServer, CN = EvilServer (untrusted)
depth=1: C = SE, ST = EvilCA, L = EvilCA, O = EvilCA, OU = EvilCA, CN = EvilCA (untrusted)
depth=2: C = SE, ST = Root, L = Root, O = Root, OU = Root, CN = Root
```
