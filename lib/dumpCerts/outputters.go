package dumpCerts

import (
	"crypto/x509"
	"fmt"
	"io"
	"sort"
	"strings"
)

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
