package main

import (
	"crypto/md5"
	"crypto/x509"
	"encoding/hex"
	"fmt"
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

func ProcessDomain(domain string, commonNames chan<- string) {
	if hosts.Mark(domain) {
		return
	}

	if !HasDNS(domain) {
		fmt.Printf(`"%s","%s"\n`, domain, "invalid DNS")
	}

}
