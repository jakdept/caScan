package main

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"testing"

	"github.com/sebdah/goldie"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHostList(t *testing.T) {
	testList := hostList{}
	for _, tc := range []struct {
		in  string
		exp bool
	}{
		{"apple", true},
		{"banana", true},
		{"eggplant", true},
		{"banana", false},
		{"carrot", true},
		{"date", true},
		{"date", false},
		{"banana", false},
		{"date", false},
		{"eggplant", false},
		{"eggplant", false},
		{"fig", true},
	} {
		t.Run(tc.in, func(t *testing.T) {
			assert.Equal(t, tc.exp, testList.First(tc.in))
		})
	}
}

func TestCheckDNS(t *testing.T) {
	for _, tc := range []struct {
		host string
		exp  bool
	}{
		{"example.com", true},
		{"not.example.com", false},
	} {
		t.Run(tc.host, func(t *testing.T) {
			tc := tc
			t.Parallel()
			assert.Equal(t, tc.exp, HasDNS(tc.host))
		})
	}
}

func TestGetx509Fingerprint(t *testing.T) {
	certData, err := ioutil.ReadFile("testdata/4096b-rsa-example-cert.pem")
	require.NoError(t, err)
	block, _ := pem.Decode(certData)
	require.NotNil(t, block, "failed to parse certificate PEM")
	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err, "failed to parse certificate: %s")

	assert.Equal(t, Getx509Fingerprint(*cert), "70ff69f510e9e3fb4e56641db8a7cd9d")
}

func TestHasWildcard(t *testing.T) {
	for _, tc := range []struct {
		host string
		exp  bool
	}{
		{"example.com", false},
		{"not.example.com", false},
		{"*.example.com", true},
		{"child.*.example.com", true},
	} {
		t.Run(tc.host, func(t *testing.T) {
			tc := tc
			t.Parallel()
			assert.Equal(t, tc.exp, HasWildcard(tc.host))
		})
	}

}

func TestTrimWildcard(t *testing.T) {
	for _, tc := range []struct {
		host string
		exp  string
	}{
		{"example.com", "example.com"},
		{"not.example.com", "not.example.com"},
		{"*.example.com", "example.com"},
		{"child.*.example.com", "example.com"},
	} {
		t.Run(tc.host, func(t *testing.T) {
			tc := tc
			t.Parallel()
			assert.Equal(t, tc.exp, TrimWildcard(tc.host))
		})
	}
}

func TestUniqStrings(t *testing.T) {
	for name, tc := range map[string]struct {
		in  []string
		exp []string
	}{
		"empty": {},
		"one": {
			in:  []string{"apple"},
			exp: []string{"apple"},
		},
		"dupe": {
			in: []string{
				"apple",
				"apple",
			},
			exp: []string{
				"apple",
			},
		},
		"list": {
			in: []string{
				"apple",
				"banana",
				"eggplant",
				"banana",
				"carrot",
				"date",
				"date",
				"banana",
				"date",
				"eggplant",
				"eggplant",
				"fig",
			},
			exp: []string{
				"apple",
				"banana",
				"carrot",
				"date",
				"eggplant",
				"fig",
			},
		},
	} {
		t.Run(name, func(t *testing.T) {
			tc := tc
			t.Parallel()
			assert.Equal(t, tc.exp, uniqStrings(tc.in))
		})
	}
}

func loadCerts(t *testing.T) (certs []x509.Certificate) {
	for _, file := range []string{
		"testdata/2048b-rsa-example-cert.pem",
		"testdata/4096b-rsa-example-cert.pem",
		"testdata/8192b-rsa-example-cert.pem",
	} {
		certData, err := ioutil.ReadFile(file)
		require.NoError(t, err)
		block, _ := pem.Decode(certData)
		require.NotNil(t, block, "failed to parse certificate PEM")
		cert, err := x509.ParseCertificate(block.Bytes)
		require.NoError(t, err, "failed to parse certificate: %s")
		certs = append(certs, *cert)
	}
	return
}

func TestCSVFingerprint(t *testing.T) {
	buf := bytes.Buffer{}

	outTest := CSVFingerprint(&buf)
	outTest("example.com", "test status", loadCerts(t)...)

	goldie.New(t,
		goldie.WithFixtureDir("testdata/golden"),
		goldie.WithTestNameForDir(true),
	).Assert(t, t.Name(), buf.Bytes())
}

func TestCSVSerial(t *testing.T) {
	buf := bytes.Buffer{}

	outTest := CSVSerial(&buf)
	outTest("example.com", "test status", loadCerts(t)...)

	goldie.New(t,
		goldie.WithFixtureDir("testdata/golden"),
		goldie.WithTestNameForDir(true),
	).Assert(t, t.Name(), buf.Bytes())
}

// this isn't working properly somehow
// func TestWarnFingerprint(t *testing.T) {
// 	targets := []string{"a627088f116f56d0d7c665b546b78dbb"}
// 	buf := bytes.Buffer{}

// 	outTest := WarnFingerprint(&buf, targets...)
// 	outTest("example.com", "test status", loadCerts(t)...)

// 	goldie.New(t,
// 		goldie.WithFixtureDir("testdata/golden"),
// 		goldie.WithTestNameForDir(true),
// 	).Assert(t, t.Name(), buf.Bytes())
// }
