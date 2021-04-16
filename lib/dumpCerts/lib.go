package dumpCerts

import (
	"crypto/md5"
	"crypto/x509"
	"encoding/hex"
	"net"
	"sort"
	"strings"
	"sync"
)

type hostList struct {
	m map[string]struct{}
	l sync.Mutex
}

// First returns true if it's the first time a given string has been seen.
func (l *hostList) First(host string) bool {
	l.l.Lock()
	defer l.l.Unlock()
	if l.m == nil {
		l.m = map[string]struct{}{}
	}
	_, present := l.m[host]
	if !present {
		l.m[host] = struct{}{}
	}
	return !present
}

var hosts hostList

// GetIPs checks a domain to see if it has an A record, or a CNAME resolving to an A record.
func GetIPs(host string) []string {
	addrs, _ := net.LookupHost(host)
	return addrs
}

// Getx509Fingerprint returns the fingerprint of a certificate.
func Getx509Fingerprint(cert x509.Certificate) string {
	fingerprint := md5.Sum(cert.Raw) //nolint only used for x509 fingerprinting
	return hex.EncodeToString(fingerprint[:])
}

type certSlice []x509.Certificate

func (s certSlice) Len() int      { return len(s) }
func (s certSlice) Swap(i, j int) { s[i], s[j] = s[j], s[i] }
func (s certSlice) Less(i, j int) bool {
	return Getx509Fingerprint(s[i]) < Getx509Fingerprint(s[j])
}

func (s certSlice) Dedup() certSlice {
	if !sort.IsSorted(s) {
		sort.Sort(s)
	}
	for i := 0; i < s.Len()-1; {
		if s[i].Equal(&s[i+1]) {
			s = append((s)[:i], s[i+1:]...)
		}
		i++
	}
	return s
}

func HasWildcard(host string) bool {
	return strings.HasPrefix(host, "*.") || strings.Contains(host, ".*.")
}

func TrimWildcard(host string) string {
	chunks := strings.Split(host, "*.")
	return chunks[len(chunks)-1]
}

func uniqStrings(s []string) []string {
	sort.Strings(s)
	for i := 0; i < len(s)-1; {
		if s[i] == s[i+1] {
			s = append(s[:i], s[i+1:]...)
		} else {
			i++
		}
	}
	return s
}
