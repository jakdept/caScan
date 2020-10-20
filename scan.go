package main

import (
	"bufio"
	"crypto/md5"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
)

var (
	csvOutput   = flag.Bool("csv", true, "print out info of CSV on every cert")
	concurrency = flag.Int("thread", 10, "number of thread workers to run")
)

func main() {
	flag.Parse()

	var outFunc OutputFunc
	var outputStream io.Writer
	outputStream = os.Stdout
	var inputStream io.Reader
	inputStream = os.Stdin

	hostChan := make(chan string)
	if *csvOutput {
		outFunc = CSV(outputStream)
		fmt.Fprintf(outputStream, `"%s","%s","%s","%s"`+"\n",
			"domain", "dnsStatus", "fingerprints", "serial")
	}

	for i := 0; i < *concurrency; i++ {
		go func() {
			for elem := range hostChan {
				GetCertificates(elem, hostChan, outFunc)
			}
		}()
	}

	for _, host := range os.Args {
		hostChan <- host
	}

	scanner := bufio.NewScanner(inputStream)
	for scanner.Scan() {
		hostChan <- scanner.Text()
	}
}

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

type OutputFunc func(domain, dnsStatus string, certs ...x509.Certificate)

func CSV(out io.Writer) OutputFunc {
	return func(domain, dnsStatus string, certs ...x509.Certificate) {
		var fingerprints []string
		var serials []string
		for _, cert := range certs {
			serials = append(serials, cert.SerialNumber.String())
			fingerprints = append(fingerprints, Getx509Fingerprint(cert))
		}
		fmt.Fprintf(out, `"%s","%s","%s","%s"`+"\n", domain, dnsStatus,
			strings.Join(fingerprints, "|"), strings.Join(serials, "|"))
	}
}

func WarnFingerprint(out io.Writer, fingerprints ...string) OutputFunc {
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
				fmt.Fprintf(out, `"%s","%s","%s"`+"\n", domain, dnsStatus,
					strings.Join(fingerprints, "|"))
			}
		}
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
		if hosts.First(domain) {
			output(domain, StatusWildcard)
		}
		domain = TrimWildcard(domain)
	}

	if !hosts.First(domain) {
		return
	}

	if !HasDNS(domain) {
		dnsStatus = StatusInvalidDNS
		output(domain, dnsStatus)
		return
	}

	domain = strings.Split(domain, ":")[0]

	conn, err := tls.Dial("tcp", domain+":443", nil)
	if err != nil {
		dnsStatus = StatusFailedConnection
		output(domain, dnsStatus)
		return
	}

	var certs certSlice
	for _, chain := range conn.ConnectionState().VerifiedChains {
		for _, cert := range chain {
			certs = append(certs, *cert)
			for _, domain := range cert.DNSNames {
				domain := domain
				go func() {
					commonNames <- domain // send when you can
				}()
			}
		}
	}
	certs = certs.Dedup()

	output(domain, dnsStatus, certs...)
}
