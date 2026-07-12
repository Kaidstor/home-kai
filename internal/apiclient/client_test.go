package apiclient

import (
	"strings"
	"testing"
)

// A bearer token must never travel over plaintext or an unpinned TLS session:
// the constructor refuses anything but https + a full fingerprint.
func TestNewRejectsInsecureConfigs(t *testing.T) {
	fp := strings.Repeat("ab", 32)
	for _, tc := range []struct{ url, fp string }{
		{"http://coord:8443", fp},                                                  // plaintext
		{"coord:8443", fp},                                                         // no scheme
		{"https://coord:8443", ""},                                                 // no pin
		{"https://coord:8443", "zz"} /* not hex */, {"https://coord:8443", "abcd"}, // short
	} {
		if _, err := New(tc.url, tc.fp, "tok"); err == nil {
			t.Errorf("New(%q, %q) must fail", tc.url, tc.fp)
		}
	}
	if _, err := New("https://coord:8443", fp, "tok"); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
}
