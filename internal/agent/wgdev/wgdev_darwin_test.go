//go:build darwin

package wgdev

import (
	"encoding/hex"
	"testing"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestParseUAPIPeers(t *testing.T) {
	k1, _ := wgtypes.GeneratePrivateKey()
	k2, _ := wgtypes.GeneratePrivateKey()
	pub1, pub2 := k1.PublicKey(), k2.PublicKey()
	raw := "private_key=" + hex.EncodeToString(k1[:]) + "\n" +
		"listen_port=51820\n" +
		"public_key=" + hex.EncodeToString(pub1[:]) + "\n" +
		"endpoint=203.0.113.7:51820\n" +
		"last_handshake_time_sec=1700000000\n" +
		"last_handshake_time_nsec=500\n" +
		"rx_bytes=123\n" +
		"tx_bytes=456\n" +
		"public_key=" + hex.EncodeToString(pub2[:]) + "\n" +
		"rx_bytes=0\n"

	peers, err := parseUAPIPeers(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(peers) != 2 {
		t.Fatalf("got %d peers, want 2", len(peers))
	}
	p := peers[0]
	if p.PublicKey != k1.PublicKey() || p.Endpoint != "203.0.113.7:51820" ||
		p.RxBytes != 123 || p.TxBytes != 456 || p.LastHandshake.Unix() != 1700000000 {
		t.Fatalf("peer 0: %+v", p)
	}
	if peers[1].PublicKey != k2.PublicKey() || peers[1].Endpoint != "" || !peers[1].LastHandshake.IsZero() {
		t.Fatalf("peer 1: %+v", peers[1])
	}
}
