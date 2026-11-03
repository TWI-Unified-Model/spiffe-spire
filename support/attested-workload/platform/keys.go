package platform

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
)

func generateP256() (*KeyPair, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("platform: generate P-256 key: %w", err)
	}
	return &KeyPair{Private: priv}, nil
}

func generateRSA2048() (*KeyPair, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("platform: generate RSA-2048 key: %w", err)
	}
	return &KeyPair{Private: priv}, nil
}
