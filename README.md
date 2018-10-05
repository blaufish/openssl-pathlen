# Path Length Constraint #

## RFC5280 Path Length Constraint §algorithm ##
6.1.2.  Initialization
```
      (k)  max_path_length:  this integer is initialized to n, is
           decremented for each non-self-issued certificate in the path,
           and may be reduced to the value in the path length constraint
           field within the basic constraints extension of a CA
           certificate.
```
6.1.4.  Preparation for Certificate i+1
```
      (l)  If the certificate was not self-issued, verify that
           max_path_length is greater than zero and decrement
           max_path_length by 1.

      (m)  If pathLenConstraint is present in the certificate and is
           less than max_path_length, set max_path_length to the value
           of pathLenConstraint.
```

## RFC5280 Self-Issued loop hole ##

What is self-issued?
```
   A certificate is self-issued if the same DN appears in the subject
   and issuer fields (the two DNs are the same if they match according
   to the rules specified in Section 7.1).  In general, the issuer and
   subject of the certificates that make up a path are different for
   each certificate.  However, a CA may issue a certificate to itself to
   support key rollover or changes in certificate policies.  These
   self-issued certificates are not counted when evaluating path length
   or name constraints.
```

i.e. Path Length Constraint can be easily circumvented in a Certificate Authority breach.

Attacker breach Certificate Authority and issue a new subordinate authority with a name
that will trigger the "self-issued" exception. This render the the constraint moot and
the mallicious subordinate authority is free to wreak mayhem upon this world.

## OpenSSL implementation ##

### Reverse order ###
OpenSSL process certificates in the reverse order compared to the RFC5280 algorithm,
i.e. processing from leaf to root.

As such, OpenSSL algorithm works by incrementing a calculated path length (plen),
instead of implementing the `max_path_length` decrementing algorithm in the RFC.

### Off-By-One ###
plen is incremented after each iteration, unless there is an exception.
So the plen counter is normally one too high, the RFC path length is X the plen value is X+1.

Therefor, there is a +1 in the openssl code base to allow for the off-by-one to succeed.

### Off-By-One not applied to self-issued non-authority ###

The following testcase forced an error where the leaf-certificate's +1 wasn't applied,
```
depth=0: C = SE, ST = EvilServer, L = EvilServer, O = EvilServer, OU = EvilServer, CN = EvilServer (untrusted)
depth=1: C = SE, ST = EvilServer, L = EvilServer, O = EvilServer, OU = EvilServer, CN = EvilServer (untrusted)
```
It was triggered by Self-issued certificate authority rule incorrectly applied to leaf in
`if (!(x->ex_flags & EXFLAG_SI))`.

A fix was proposed in [OpenSSL Pull 7353](https://github.com/openssl/openssl/pull/7353)

# Trace #

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
