package coordinator

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCertReloader(t *testing.T) {
	dirA, dirB := t.TempDir(), t.TempDir()
	certA, err := LoadOrCreateCert(dirA, []string{"127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	certB, err := LoadOrCreateCert(dirB, []string{"127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	fpA, _ := CertFingerprint(certA)
	fpB, _ := CertFingerprint(certB)
	if fpA == fpB {
		t.Fatal("test certs must differ")
	}

	serveDir := t.TempDir()
	certPath := filepath.Join(serveDir, "fullchain.pem")
	keyPath := filepath.Join(serveDir, "privkey.pem")
	copyFile := func(dst, src string) {
		t.Helper()
		b, err := os.ReadFile(src)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(dst, b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	copyFile(certPath, filepath.Join(dirA, "coordinator.crt"))
	copyFile(keyPath, filepath.Join(dirA, "coordinator.key"))

	r, err := NewCertReloader(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	got, err := r.GetCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	if fp, _ := CertFingerprint(*got); fp != fpA {
		t.Fatalf("initial cert: %s, want %s", fp, fpA)
	}

	// Swap the files on disk (renewal) and make the mtime visibly newer.
	copyFile(certPath, filepath.Join(dirB, "coordinator.crt"))
	copyFile(keyPath, filepath.Join(dirB, "coordinator.key"))
	future := time.Now().Add(time.Hour)
	if err := os.Chtimes(certPath, future, future); err != nil {
		t.Fatal(err)
	}
	r.lastStat = time.Time{} // bypass the stat throttle

	got, err = r.GetCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	if fp, _ := CertFingerprint(*got); fp != fpB {
		t.Fatalf("cert after renewal: %s, want %s", fp, fpB)
	}
}
