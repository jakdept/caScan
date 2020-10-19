package main

import (
	"crypto/md5"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"sort"
	"strings"
	"sync"
)

type hostList struct {
	m map[string]struct{}
	l sync.RWMutex
}

func (l *hostList) Mark(host string) bool {
	l.l.RLock()
	defer l.l.RUnlock()
	if l.m == nil {
		l.m = map[string]struct{}{}
	}
	_, ok := l.m[host]
	if !ok {
		l.m[host] = struct{}{}
	}
	return ok
}

var hosts hostList

// HasDNS checks a domain to see if it has an A record, or a CNAME resolving to an A record.
func HasDNS(host string) bool {
	addrs, _ := net.LookupHost(host)
	return len(addrs) > 0
}

// Getx509Fingerprint returns the fingerprint of a certificate.
func Getx509Fingerprint(cert x509.Certificate) string {
	fingerprint := md5.Sum(cert.Raw)
	return hex.EncodeToString(fingerprint[:])
}

func HasWildcard(host string) bool {
	return strings.HasPrefix(host, "*.") || strings.Contains(host, ".*.")
}

func TrimWildcard(host string) string {
	chunks := strings.Split(host, "*.")
	return chunks[len(chunks)-1]
}

func uniqStrings(in []string) []string {
	sort.Strings(in)
	for i := 1; i < len(in); {
		if in[i-1] == in[i] {
			in = append(in[:i-1], in[i:]...)
		} else {
			i++
		}
	}
	return in
}

type OutputFunc func(domain, dnsStatus string, certs ...x509.Certificate)

func WarnFingerprintCSV(out io.Writer, fingerprints ...string) OutputFunc {
	sort.Strings(fingerprints)
	search := func(target string) bool {
		i := sort.SearchStrings(fingerprints, target)
		if i > 0 && i < len(fingerprints) && fingerprints[i] == target {
			return true
		}
		return false
	}

	return func(domain, dnsStatus string, certs ...x509.Certificate) {
		for _, cert := range certs {
			certFP := Getx509Fingerprint(cert)
			if search(certFP) {
				fmt.Fprintf(out, `"%s","%s","%s"`, domain, dnsStatus,
					strings.Join(fingerprints, "|"))
			}
		}
	}
}

func WriteFingerprintCSV(out io.Writer) OutputFunc {
	return func(domain, dnsStatus string, certs ...x509.Certificate) {
		var fingerprints []string
		for _, cert := range certs {
			fingerprints = append(fingerprints, Getx509Fingerprint(cert))
		}
		fmt.Fprintf(out, `"%s","%s","%s"`, domain, dnsStatus,
			strings.Join(fingerprints, "|"))
	}
}

func WriteSerialCSV(out io.Writer) OutputFunc {
	return func(domain, dnsStatus string, certs ...x509.Certificate) {
		var serials []string
		for _, cert := range certs {
			serials = append(serials, cert.SerialNumber.String())
		}
		fmt.Fprintf(out, `"%s","%s","%s"`, domain, dnsStatus,
			strings.Join(serials, "|"))
	}
}

const (
	StatusInvalidDNS       = "invalid dns"
	StatusValidDNS         = "valid dns"
	StatusWildcard         = "wildcard"
	StatusFailedConnection = "failed connection"
)

func GetCertificates(domain string, commonNames chan<- string, output OutputFunc) {
	dnsStatus := StatusValidDNS
	if HasWildcard(domain) {
		dnsStatus = StatusWildcard
		domain = TrimWildcard(domain)
	}

	if hosts.Mark(domain) {
		return
	}

	if !HasDNS(domain) {
		dnsStatus = StatusInvalidDNS
		output(domain, dnsStatus)
		return
	}

	conn, err := tls.Dial("tcp", domain, nil)
	if err != nil {
		dnsStatus = StatusFailedConnection
		output(domain, dnsStatus)
		return
	}

	certMap := make(map[string]x509.Certificate)
	var certSlice []x509.Certificate
	for _, chain := range conn.ConnectionState().VerifiedChains {
		for _, cert := range chain {
			certMap[Getx509Fingerprint(*cert)] = *cert
			for _, domain := range cert.DNSNames {
				commonNames <- domain
			}
		}
	}

	for _, each := range certMap {
		certSlice = append(certSlice, each)
	}
	output(domain, dnsStatus, certSlice...)
}
