package wgdev

import (
	"fmt"
	"net"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func toWGPeerConfigs(peers []PeerConfig) ([]wgtypes.PeerConfig, error) {
	out := make([]wgtypes.PeerConfig, 0, len(peers))
	for _, p := range peers {
		pc := wgtypes.PeerConfig{PublicKey: p.PublicKey, ReplaceAllowedIPs: true}
		for _, pfx := range p.AllowedIPs {
			pc.AllowedIPs = append(pc.AllowedIPs, net.IPNet{
				IP:   pfx.Masked().Addr().AsSlice(),
				Mask: net.CIDRMask(pfx.Bits(), pfx.Addr().BitLen()),
			})
		}
		if p.Endpoint != "" {
			ua, err := net.ResolveUDPAddr("udp", p.Endpoint)
			if err != nil {
				return nil, fmt.Errorf("resolve endpoint %q: %w", p.Endpoint, err)
			}
			pc.Endpoint = ua
		}
		if p.Keepalive > 0 {
			ka := p.Keepalive
			pc.PersistentKeepaliveInterval = &ka
		}
		out = append(out, pc)
	}
	return out, nil
}

func toPeerStatuses(peers []wgtypes.Peer) []PeerStatus {
	out := make([]PeerStatus, 0, len(peers))
	for _, p := range peers {
		st := PeerStatus{
			PublicKey:     p.PublicKey,
			LastHandshake: p.LastHandshakeTime,
			RxBytes:       p.ReceiveBytes,
			TxBytes:       p.TransmitBytes,
		}
		if p.Endpoint != nil {
			st.Endpoint = p.Endpoint.String()
		}
		out = append(out, st)
	}
	return out
}
