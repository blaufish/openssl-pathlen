Testcase that triggers a Path Length Constraint evaulation error

* Leaf is a normal certificate, not a Certificate Authority.
* Leaf naming matches "Self Issued" check.

OpenSSL will calculate plen (`plen` is intended to be `Path Length + 1`) to 1, which does not trigger the check;
* `plen=0`; `EXFLAG_SI=yes`; depth=0: C = SE, ST = EvilServer, L = EvilServer, O = EvilServer, OU = EvilServer, CN = EvilServer (untrusted)
* `plen=0`; `EXFLAG_SI=no `; depth=1: C = SE, ST = EvilServer, L = EvilServer, O = EvilServer, OU = EvilServer, CN = EvilServer (untrusted)
* `plen=1` (i.e. the actual Path Length), expected value was `plen=2` (i.e. Path Length + 1), any Path Length Constraint check will fail due to off-by-one error.

The following values will be set the when checking the constraint:
```
*** check_chain_extensions:523 i=2
*** check_chain_extensions:524 plen=1
*** check_chain_extensions:525 x->ex_pathlen=0
```

The following values will be evaluated:
```
*** check_chain_extensions:527 i > 1=1
*** check_chain_extensions:528 !(x->ex_flags & EXFLAG_SI)=1
*** check_chain_extensions:529 (x->ex_pathlen != -1)=1
*** check_chain_extensions:530 (plen > (x->ex_pathlen + proxy_path_length + 1))=0
```

