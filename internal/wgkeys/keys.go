// Package wgkeys wraps WireGuard key generation and parsing.
package wgkeys

import "golang.zx2c4.com/wireguard/wgctrl/wgtypes"

type Pair struct {
	Private wgtypes.Key
	Public  wgtypes.Key
}

func Generate() (Pair, error) {
	priv, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return Pair{}, err
	}
	return Pair{Private: priv, Public: priv.PublicKey()}, nil
}

func ParsePublic(s string) (wgtypes.Key, error)  { return wgtypes.ParseKey(s) }
func ParsePrivate(s string) (wgtypes.Key, error) { return wgtypes.ParseKey(s) }
