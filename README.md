# caScan
Scan domains for a certificate in the verified chain.

Feed this tool a list of domains on stdin (or see `--help`) and all matching domains are printed out.

Example:
```
cat domains.list | caScan -csv | tee caFingerprints.csv
```
