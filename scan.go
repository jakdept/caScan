package main

import (
	"crypto/md5"
	"crypto/x509"
	"encoding/hex"
	"net"
	"strings"
)

// CheckDNS checks a domain to see if it has an A record, or a CNAME resolving to an A record.
func CheckDNS(host string) bool {
	addrs, _ := net.LookupHost(host)
	return len(addrs) > 0
}

// Getx509Fingerprint returns the fingerprint of a certificate.
func Getx509Fingerprint(cert x509.Certificate) string {
	fingerprint := md5.Sum(cert.Raw)
	return hex.EncodeToString(fingerprint[:])
}

func TrimWildcard(host string) string {
	chunks := strings.Split(host, "*.")
	return chunks[len(chunks)-1]
}
