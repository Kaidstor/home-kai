// kai-coordinator is the control plane of the kai overlay network.
//
//	kai-coordinator -config /etc/kai/coordinator.toml
//	kai-coordinator gen-admin-token
package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/kaidstor/home-kai/internal/coordinator"
	"github.com/kaidstor/home-kai/internal/coordinator/dns"
	"github.com/kaidstor/home-kai/internal/coordinator/store"
)

type fileConfig struct {
	Listen         string `toml:"listen"`     // ":8443"
	PublicURL      string `toml:"public_url"` // "https://vpn.example.com:8443"
	DataDir        string `toml:"data_dir"`   // "/var/lib/kai"
	OverlayCIDR    string `toml:"overlay_cidr"`
	HubEndpoint    string `toml:"hub_endpoint"` // "vpn.example.com:51820"
	MTU            int    `toml:"mtu"`
	AdminTokenHash string `toml:"admin_token_hash"`
	DNS            struct {
		Provider string `toml:"provider"` // "timeweb" | "none"
		Token    string `toml:"token"`
		Zone     string `toml:"zone"`   // registered domain in the provider
		Domain   string `toml:"domain"` // suffix for device names, defaults to zone
	} `toml:"dns"`
	// UI is an optional extra HTTPS listener with a publicly trusted (e.g.
	// Let's Encrypt) certificate, so browsers open the web UI without a
	// self-signed warning. Agents keep using the pinned listener.
	UI struct {
		Listen   string `toml:"listen"` // e.g. ":8444"; empty disables
		CertFile string `toml:"cert_file"`
		KeyFile  string `toml:"key_file"`
	} `toml:"ui"`
	// RequireApproval holds new nodes out of the network until an admin
	// approves them in the UI.
	RequireApproval bool `toml:"require_approval"`
	// EventWebhook receives a JSON POST per activity-log event (SIEM/чат).
	EventWebhook string `toml:"event_webhook"`
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "gen-admin-token" {
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			fatal(err)
		}
		token := hex.EncodeToString(b)
		sum := sha256.Sum256([]byte(token))
		fmt.Printf("admin token:      %s\nadmin_token_hash: %s\n", token, hex.EncodeToString(sum[:]))
		fmt.Println("\nPut admin_token_hash into coordinator.toml and keep the token itself for the kai CLI.")
		return
	}

	configPath := flag.String("config", "/etc/kai/coordinator.toml", "path to TOML config")
	flag.Parse()

	var cfg fileConfig
	if _, err := toml.DecodeFile(*configPath, &cfg); err != nil {
		fatal(fmt.Errorf("read config: %w", err))
	}
	if cfg.Listen == "" {
		cfg.Listen = ":8443"
	}
	if cfg.DataDir == "" {
		cfg.DataDir = "/var/lib/kai"
	}
	if cfg.OverlayCIDR == "" {
		cfg.OverlayCIDR = "100.87.0.0/16"
	}
	for name, v := range map[string]string{
		"public_url": cfg.PublicURL, "hub_endpoint": cfg.HubEndpoint, "admin_token_hash": cfg.AdminTokenHash,
	} {
		if v == "" {
			fatal(fmt.Errorf("config: %s is required", name))
		}
	}
	overlay, err := netip.ParsePrefix(cfg.OverlayCIDR)
	if err != nil {
		fatal(fmt.Errorf("config: bad overlay_cidr: %w", err))
	}

	log := slog.New(slog.NewTextHandler(os.Stderr, nil))

	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		fatal(err)
	}
	st, err := store.Open(filepath.Join(cfg.DataDir, "kai.db"))
	if err != nil {
		fatal(err)
	}
	defer st.Close()

	pubHost := ""
	if u, err := url.Parse(cfg.PublicURL); err == nil {
		pubHost = u.Hostname()
	}
	cert, err := coordinator.LoadOrCreateCert(cfg.DataDir, []string{pubHost})
	if err != nil {
		fatal(err)
	}
	fp, err := coordinator.CertFingerprint(cert)
	if err != nil {
		fatal(err)
	}

	var provider dns.Provider = dns.Noop{}
	domain := ""
	if cfg.DNS.Provider == "timeweb" {
		if cfg.DNS.Token == "" || cfg.DNS.Zone == "" {
			fatal(fmt.Errorf("config: dns.token and dns.zone are required for provider=timeweb"))
		}
		provider = dns.NewTimeweb(cfg.DNS.Zone, cfg.DNS.Token)
		domain = cfg.DNS.Domain
		if domain == "" {
			domain = cfg.DNS.Zone
		}
	}

	srv := coordinator.NewServer(coordinator.Config{
		PublicURL:       cfg.PublicURL,
		HubEndpoint:     cfg.HubEndpoint,
		OverlayCIDR:     overlay,
		MTU:             cfg.MTU,
		AdminTokenHash:  cfg.AdminTokenHash,
		Domain:          domain,
		Fingerprint:     fp,
		EventWebhook:    cfg.EventWebhook,
		RequireApproval: cfg.RequireApproval,
	}, st, provider, log)

	handler := srv.Handler()

	// Optional UI listener with a publicly trusted cert (hot-reloaded from
	// disk — LE short-lived certs rotate without a coordinator restart).
	if cfg.UI.Listen != "" {
		if cfg.UI.CertFile == "" || cfg.UI.KeyFile == "" {
			fatal(fmt.Errorf("config: ui.cert_file and ui.key_file are required when ui.listen is set"))
		}
		reloader, err := coordinator.NewCertReloader(cfg.UI.CertFile, cfg.UI.KeyFile)
		if err != nil {
			fatal(fmt.Errorf("ui cert: %w", err))
		}
		uiSrv := &http.Server{
			Addr:              cfg.UI.Listen,
			Handler:           handler,
			TLSConfig:         &tls.Config{GetCertificate: reloader.GetCertificate, MinVersion: tls.VersionTLS12},
			ReadHeaderTimeout: 10 * time.Second,
		}
		log.Info("kai-coordinator UI listening", "addr", cfg.UI.Listen, "cert", cfg.UI.CertFile)
		go func() {
			// The UI listener is auxiliary: losing it must not take down the
			// agent-facing listener (the data plane control loop).
			if err := uiSrv.ListenAndServeTLS("", ""); err != nil {
				log.Error("ui listener failed — web UI unavailable on this port", "addr", cfg.UI.Listen, "err", err)
			}
		}()
	}

	httpSrv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           handler,
		TLSConfig:         &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12},
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Info("kai-coordinator listening", "addr", cfg.Listen, "fingerprint", fp, "overlay", overlay.String(), "dns", cfg.DNS.Provider)
	if err := httpSrv.ListenAndServeTLS("", ""); err != nil {
		fatal(err)
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "kai-coordinator:", err)
	os.Exit(1)
}
