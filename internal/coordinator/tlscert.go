package coordinator

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// LoadOrCreateCert returns the coordinator's self-signed TLS cert, generating
// it on first start. Agents authenticate the coordinator by pinning the
// SHA-256 fingerprint of this cert (delivered out-of-band inside the join
// command), so SANs are informational only.
func LoadOrCreateCert(dataDir string, hosts []string) (tls.Certificate, error) {
	certPath := filepath.Join(dataDir, "coordinator.crt")
	keyPath := filepath.Join(dataDir, "coordinator.key")

	if _, err := os.Stat(certPath); err == nil {
		return tls.LoadX509KeyPair(certPath, keyPath)
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "kai-coordinator"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else if h != "" {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		return tls.Certificate{}, err
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return tls.Certificate{}, err
	}
	return tls.X509KeyPair(certPEM, keyPEM)
}

// CertReloader serves a certificate from disk and re-reads it when the file
// changes. Needed for the UI listener: Let's Encrypt short-lived IP certs
// rotate every few days, and restarting the coordinator to pick them up would
// drop all in-memory UI sessions.
type CertReloader struct {
	certPath, keyPath string

	mu       sync.Mutex
	cert     *tls.Certificate
	modTime  time.Time
	lastStat time.Time
}

// certStatInterval bounds how often GetCertificate stats the cert file.
const certStatInterval = 30 * time.Second

func NewCertReloader(certPath, keyPath string) (*CertReloader, error) {
	r := &CertReloader{certPath: certPath, keyPath: keyPath}
	if err := r.reload(); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *CertReloader) reload() error {
	st, err := os.Stat(r.certPath)
	if err != nil {
		return err
	}
	cert, err := tls.LoadX509KeyPair(r.certPath, r.keyPath)
	if err != nil {
		return err
	}
	r.cert = &cert
	r.modTime = st.ModTime()
	return nil
}

// GetCertificate plugs into tls.Config. On reload failure it keeps serving
// the previous cert — a half-written renewal must not take the UI down.
func (r *CertReloader) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if time.Since(r.lastStat) > certStatInterval {
		r.lastStat = time.Now()
		if st, err := os.Stat(r.certPath); err == nil && !st.ModTime().Equal(r.modTime) {
			_ = r.reload()
		}
	}
	return r.cert, nil
}

// CertFingerprint is the lowercase hex SHA-256 of the leaf certificate DER —
// the value agents pin.
func CertFingerprint(cert tls.Certificate) (string, error) {
	if len(cert.Certificate) == 0 {
		return "", fmt.Errorf("empty certificate chain")
	}
	sum := sha256.Sum256(cert.Certificate[0])
	return hex.EncodeToString(sum[:]), nil
}
