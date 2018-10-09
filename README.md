# Path Length Constraint #
* RFC5820 Path Length Constraint Algorithm
* OpenSSL implementation of RFC5820 algorithm
* OpenSSL implementation bugs and fixes in pull request by vdukhovni


## RFC5280 Path Length Constraint algorithm ##
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

### RFC5280 Self-Issued loop hole ###

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

### RFC5280 Should trust anchor certificate be processed or not? ###

Some users on openssl-users thinks the trust anchor certificate should not be expected to
be processed. A fair reading of the various relevant parts of the RFC seems to indicate
that it is strongly RECOMMENDED but not necesserily REQUIRED. But clearly expressed
normative RFC2119 wording is missing in RFC5280.

In my humble opinion, the intent of RFC5280 is pretty clear, any CA certificate including
self-signed root, is recommended to be processed. So the first cert in the certificate path
validation ought to be the trust anchor certificate.

Relevant section, this section might be interprented differently by different readers:
```
   In Section 6.1, the text describes basic path validation.  Valid
   paths begin with certificates issued by a trust anchor.  The
   algorithm requires the public key of the CA, the CA's name, and any
   constraints upon the set of paths that may be validated using this
   key.
```

Relevant section, this section appears to clarify that e.g. self signed trust
anchor certificate is to be processed:
```
   Where a CA distributes self-signed certificates to specify trust
   anchor information, certificate extensions can be used to specify
   recommended inputs to path validation.  For example, a policy
   constraints extension could be included in the self-signed
   certificate to indicate that paths beginning with this trust anchor
   should be trusted only for the specified policies.
```

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

## OpenSSL bug fixes ##

[pull/7353](https://github.com/openssl/openssl/pull/7353) by [Viktor Dukhovni](https://github.com/vdukhovni) addresses these issues:
* Testcase 1 "self issued leaf" messed up path length calculations, constraints could be violated.
* Testcase 2 path length constraint ignored for self issued certificates in chain.
* plen counter simplified to be the path length value. (no off by 1).

## OpenSSL Bug 1: Off-By-One not applied to self-issued non-authority ##

[Testcase\_1](testcase_1)

The following testcase forced an error where the leaf-certificate's +1 wasn't applied,
```
depth=0: C = SE, ST = EvilServer, L = EvilServer, O = EvilServer, OU = EvilServer, CN = EvilServer (untrusted)
depth=1: C = SE, ST = EvilServer, L = EvilServer, O = EvilServer, OU = EvilServer, CN = EvilServer (untrusted)
```
It was triggered by Self-issued certificate authority rule incorrectly applied to leaf in
`if (!(x->ex_flags & EXFLAG_SI))` leading to `plen++` not being applied.

```
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
*** check_chain_extensions:524 plen=0 <--- bug is here. plen=1 was expected, but plen++ not executed in previous iteration.
*** check_chain_extensions:525 x->ex_pathlen=-1
******* if statement components *******
*** check_chain_extensions:527 i > 1=0
*** check_chain_extensions:528 !(x->ex_flags & EXFLAG_SI)=1
*** check_chain_extensions:529 (x->ex_pathlen != -1)=0
```

A fix was proposed in [OpenSSL Pull 7353](https://github.com/openssl/openssl/pull/7353)

## OpenSSL Bug 2: Contrainst ignored when checking Root and other Self-Issued certificates ##

[Testcase\_2](testcase_2)

Path Length Constraint set by Root (and any other self-issued authority) is ignored.

```
******* important variables *******
*** check_chain_extensions:524 i=2
*** check_chain_extensions:525 plen=2
*** check_chain_extensions:526 x->ex_pathlen=0
******* if statement components *******
*** check_chain_extensions:528 i > 1=1
*** check_chain_extensions:529 !(x->ex_flags & EXFLAG_SI)=0 <-- bug is here. constraint check ignored.
*** check_chain_extensions:530 (x->ex_pathlen != -1)=1
*** check_chain_extensions:531 (plen > (x->ex_pathlen + proxy_path_length + 1))=1
evilserver.pem: OK
Chain:
depth=0: C = SE, ST = EvilServer, L = EvilServer, O = EvilServer, OU = EvilServer, CN = EvilServer (untrusted)
depth=1: C = SE, ST = EvilCA, L = EvilCA, O = EvilCA, OU = EvilCA, CN = EvilCA (untrusted)
depth=2: C = SE, ST = Root, L = Root, O = Root, OU = Root, CN = Root
```
