package main

import (
	"bufio"
	"crypto/md5" //nolint - only used for x509 fingerprinting
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
	"time"
)

var (
	csvOutput  = flag.Bool("csv", true, "print out info of CSV on every cert")
	tlsTimeout = flag.Duration("timeout", time.Second, "timeout for tls connection")
)

func main() {
	flag.Parse()

	var outFunc OutputFunc
	outputStream := io.Writer(os.Stdout)
	inputStream := io.Reader(os.Stdin)

	if *csvOutput {
		outFunc = CSV(outputStream)
		fmt.Fprintf(outputStream, `"%s","%s","%s","%s"`+"\n",
			"domain", "dnsStatus", "fingerprints", "serial")
	}

	for _, host := range flag.Args() {
		GetCertificates(host, outFunc)
	}

	fi, _ := os.Stdin.Stat()
	if (fi.Mode() & os.ModeCharDevice) == 0 {
		scanner := bufio.NewScanner(inputStream)
		for scanner.Scan() {
			GetCertificates(scanner.Text(), outFunc)
		}
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

type OutputFunc func(domain, ip, dnsStatus string, certs ...x509.Certificate)

func CSV(out io.Writer) OutputFunc {
	return func(domain, ip, dnsStatus string, certs ...x509.Certificate) {
		var fingerprints []string
		var serials []string
		for _, cert := range certs {
			serials = append(serials, cert.SerialNumber.String())
			fingerprints = append(fingerprints, Getx509Fingerprint(cert))
		}
		fmt.Fprintf(out, `"%s","%s","%s","%s","%s"`+"\n", domain, ip, dnsStatus,
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

	return func(domain, ip, dnsStatus string, certs ...x509.Certificate) {
		for _, cert := range certs {
			certFP := Getx509Fingerprint(cert)
			if search(certFP) {
				fmt.Fprintf(out, `"%s","%s","%s","%s"`+"\n", domain, ip, dnsStatus,
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

func GetCertificates(domain string, output OutputFunc) {
	// remove the port from the domain, if present
	domain = strings.TrimSuffix(domain, ":")

	dnsStatus := StatusValidDNS
	if HasWildcard(domain) {
		// launch the parent domain
		go GetCertificates(TrimWildcard(domain), output)
		// replace the wildcard and continue
		domain = "wildcard." + TrimWildcard(domain)
	}

	if !hosts.First(domain) {
		return
	}

	// enumerate the ip addresses for the domain
	ips := GetIPs(domain)
	// if there are none, do that.
	if len(ips) < 1 {
		dnsStatus = StatusInvalidDNS
		output(domain, "0.0.0.0", dnsStatus)
		return
	}

	for _, ip := range GetIPs(domain) {
		// otherwise, hit on each IP
		dialer := &net.Dialer{Timeout: *tlsTimeout}
		conn, err := tls.DialWithDialer(dialer, "tcp", domain+":443", nil)
		if err != nil {
			dnsStatus = StatusFailedConnection
			output(domain, "0.0.0.0", dnsStatus)
			return
		}

		var certs certSlice
		for _, chain := range conn.ConnectionState().VerifiedChains {
			for _, cert := range chain {
				certs = append(certs, *cert)
				for _, domain := range cert.DNSNames {
					domain := domain
					go GetCertificates(domain, output)
				}
			}
		}
		certs = certs.Dedup()

		output(domain, ip, dnsStatus, certs...)
	}
}
