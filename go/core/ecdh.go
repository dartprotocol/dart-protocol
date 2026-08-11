package core

import (
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"math/big"
)

type ECDH struct {
	priv []byte
	x    *big.Int
	y    *big.Int
}

func NewECDH() (*ECDH, error) {
	priv, x, y, err := elliptic.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return &ECDH{priv: priv, x: x, y: y}, nil
}

// NewECDHFromPrivate rebuilds the keypair from a 32-byte P-256 private scalar,
// so the server's identity key can be persisted across restarts.
func NewECDHFromPrivate(priv []byte) (*ECDH, error) {
	if len(priv) != 32 {
		return nil, errors.New("invalid private key length")
	}
	x, y := elliptic.P256().ScalarBaseMult(priv)
	if x == nil || y == nil {
		return nil, errors.New("invalid private key")
	}
	return &ECDH{priv: priv, x: x, y: y}, nil
}

func (e *ECDH) GetPrivateKey() []byte {
	return e.priv
}

func (e *ECDH) GetPublicKey() []byte {
	return elliptic.Marshal(elliptic.P256(), e.x, e.y)
}

func (e *ECDH) ComputeSecret(peerPubKey []byte) ([]byte, error) {
	px, py := elliptic.Unmarshal(elliptic.P256(), peerPubKey)
	if px == nil || py == nil {
		return nil, errors.New("invalid peer public key")
	}

	zx, _ := elliptic.P256().ScalarMult(px, py, e.priv)
	
	// Ensure the secret is always 32 bytes (pad with leading zeros if necessary)
	secret := zx.Bytes()
	if len(secret) < 32 {
		padded := make([]byte, 32)
		copy(padded[32-len(secret):], secret)
		return padded, nil
	}
	return secret[:32], nil
}
