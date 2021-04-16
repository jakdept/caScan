package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/jakdept/caScan/lib/dumpCerts"
)

func main() {
	flag.Parse()
	var output dumpCerts.OutputFunc = func(domain, ip, dnsStatus string, certs ...x509.Certificate) {
		color.Green(fmt.Sprintf("%s to %s at %s", dnsStatus, domain, ip))
		for _, cert := range certs {
			ShowCert(cert)
		}
	}

	for _, domain := range flag.Args() {
		GetReturnedCerts(domain, output)
	}
}

func ShowCert(cert x509.Certificate) {
	fmt.Printf("%s issued by %s\n", cert.Subject, cert.Issuer)
	fmt.Printf("\tNot after: %s\n", cert.NotAfter.Format(time.RFC3339))
	fmt.Printf("\tdomains: %s\n", strings.Join(cert.DNSNames, " "))
	fmt.Printf("\tfingerprint: %s\n", dumpCerts.Getx509Fingerprint(cert))
}

func GetReturnedCerts(domain string, output dumpCerts.OutputFunc) {
	// remove the port from the domain, if present
	domain = strings.TrimSuffix(domain, ":")

	dnsStatus := "valid"
	for _, ip := range dumpCerts.GetIPs(domain) {
		// otherwise, hit on each IP
		conn, err := net.DialTCP("tcp", nil, &net.TCPAddr{IP: net.ParseIP(ip), Port: 443})
		if err != nil {
			output(domain, ip, dumpCerts.StatusFailedConnection)
			continue
		}
		if err = conn.SetDeadline(time.Now().Add(time.Second)); err != nil {
			output(domain, ip, dumpCerts.StatusFailedConnection)
			continue
		}
		client := tls.Client(conn, &tls.Config{ServerName: domain, InsecureSkipVerify: true})
		if err = client.Handshake(); err != nil {
			output(domain, ip, dumpCerts.StatusFailedTLSHandshake)
			continue
		}
		var certs []x509.Certificate
		for _, newCert := range client.ConnectionState().PeerCertificates {
			certs = append(certs, *newCert)
		}

		output(domain, ip, dnsStatus, certs...)
	}
}
