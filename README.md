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
******* important variables *******
*** check_chain_extensions:523 i=0
*** check_chain_extensions:524 plen=0
*** check_chain_extensions:525 x->ex_pathlen=-1
******* if statement components *******
*** check_chain_extensions:527 i > 1=0
*** check_chain_extensions:528 !(x->ex_flags & EXFLAG_SI)=0
*** check_chain_extensions:529 (x->ex_pathlen != -1)=0
*** check_chain_extensions:530 (plen > (x->ex_pathlen + proxy_path_length + 1))=0
******* important variables *******
*** check_chain_extensions:523 i=1
*** check_chain_extensions:524 plen=0
*** check_chain_extensions:525 x->ex_pathlen=-1
******* if statement components *******
*** check_chain_extensions:527 i > 1=0
*** check_chain_extensions:528 !(x->ex_flags & EXFLAG_SI)=1
*** check_chain_extensions:529 (x->ex_pathlen != -1)=0
*** check_chain_extensions:530 (plen > (x->ex_pathlen + proxy_path_length + 1))=0
******* important variables *******
*** check_chain_extensions:523 i=2
*** check_chain_extensions:524 plen=1
*** check_chain_extensions:525 x->ex_pathlen=0
******* if statement components *******
*** check_chain_extensions:527 i > 1=1
*** check_chain_extensions:528 !(x->ex_flags & EXFLAG_SI)=1
*** check_chain_extensions:529 (x->ex_pathlen != -1)=1
*** check_chain_extensions:530 (plen > (x->ex_pathlen + proxy_path_length + 1))=0
******* important variables *******
*** check_chain_extensions:523 i=3
*** check_chain_extensions:524 plen=2
*** check_chain_extensions:525 x->ex_pathlen=1
******* if statement components *******
*** check_chain_extensions:527 i > 1=1
*** check_chain_extensions:528 !(x->ex_flags & EXFLAG_SI)=0
*** check_chain_extensions:529 (x->ex_pathlen != -1)=1
*** check_chain_extensions:530 (plen > (x->ex_pathlen + proxy_path_length + 1))=0
evilserver.pem: OK
```
