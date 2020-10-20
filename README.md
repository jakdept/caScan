# caScan
Scan domains for a certificate in the verified chain.

Feed this tool a list of domains on stdin (or see `--help`) and all matching domains are printed out.

Example:
```
cat domains.list | caScan -csv | tee caFingerprints.csv
```

* With invalid DNS, it'll prit out a line with that.
* With a wildcard domain, it'll print wildcard, and run again with the wildcard removed.
* If a domain has already been processed, it's skipped.
* With remaining domains, a TLS connection is made to `tcp:443`
  * Fingerprints & serials for certs in the verified chain are printed (joined by `|`)
  * any CN domains on the cert are also processed.
