package dumpCerts

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"strings"
	"time"
)

const (
	NoIP                     = "127.0.0.127"
	StatusInvalidDNS         = "invalid dns"
	StatusValidDNS           = "valid dns"
	StatusWildcard           = "wildcard"
	StatusFailedConnection   = "failed connection"
	StatusFailedTLSHandshake = "failed tls handshake"
)

var tlsTimeout time.Duration = time.Second

type OutputFunc func(domain, ip, dnsStatus string, certs ...x509.Certificate)

func GetCertificates(domain string, output OutputFunc) {
	// remove the port from the domain, if present
	domain = strings.TrimSuffix(domain, ":")

	dnsStatus := StatusValidDNS
	if HasWildcard(domain) {
		// launch the parent domain
		go GetCertificates(TrimWildcard(domain), output)
		// output a line for the wildcard
		output(domain, NoIP, StatusWildcard)
		// replace the wildcard and continue with a likely bunk subdomain
		domain = "wildcard." + TrimWildcard(domain)
	}

	// if this domain's already been run, skip
	if !hosts.First(domain) {
		return
	}

	// enumerate the ip addresses for the domain
	ips := GetIPs(domain)
	// if there are none, do that.
	if len(ips) < 1 {
		dnsStatus = StatusInvalidDNS
		output(domain, NoIP, dnsStatus)
		return
	}

	for _, ip := range GetIPs(domain) {
		// otherwise, hit on each IP
		conn, err := net.DialTCP("tcp", nil, &net.TCPAddr{IP: net.ParseIP(ip), Port: 443})
		if err != nil {
			output(domain, ip, StatusFailedConnection)
			continue
		}
		if err = conn.SetDeadline(time.Now().Add(tlsTimeout)); err != nil {
			output(domain, ip, StatusFailedConnection)
			continue
		}
		client := tls.Client(conn, &tls.Config{ServerName: domain})
		if err = client.Handshake(); err != nil {
			output(domain, ip, StatusFailedTLSHandshake)
			continue
		}

		var certs certSlice
		for _, chain := range client.ConnectionState().VerifiedChains {
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
