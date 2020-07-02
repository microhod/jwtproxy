package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
)

// generatePrivateKey creates a RSA Private Key of specified byte size
func GeneratePrivateKey(bitSize int) (*rsa.PrivateKey, error) {
	// Private Key generation
	privateKey, err := rsa.GenerateKey(rand.Reader, bitSize)
	if err != nil {
		return nil, err
	}

	// Validate Private Key
	err = privateKey.Validate()
	if err != nil {
		return nil, err
	}

	return privateKey, nil
}

// generatePublicKey take a rsa.PublicKey and return bytes suitable for writing to .pub file
// returns in the format "ssh-rsa ..."
func EncodePublicKeyToPEM(publicKey *rsa.PublicKey) ([]byte, error) {
	pubDer, err := x509.MarshalPKIXPublicKey(publicKey)

	if err != nil {
		return nil, err
	}

	// pem.Block
	pubBlock := pem.Block{
		Type:    "PUBLIC KEY",
		Headers: nil,
		Bytes:   pubDer,
	}

	// Private key in PEM format
	publicPEM := pem.EncodeToMemory(&pubBlock)

	return publicPEM, nil
}
