package main

import (
	"testing"
	"crypto/rsa"

	jwt "github.com/dgrijalva/jwt-go"
)

func TestGeneratePrivateKey(t *testing.T) {
	tests := []struct {
		name    string
		bitsize int
	}{
		{
			name:    "2048 Bit Size",
			bitsize: 2048,
		},
	}

	for _, test := range tests {
		p, err := GeneratePrivateKey(test.bitsize)
		if err != nil {
			t.Errorf("%s: Could not generate private key, got error: %s", test.name, err.Error())
		}
		err = p.Validate()
		if err != nil {
			t.Errorf("%s: Private Key failed validation with error: %s", test.name, err.Error())
		}
	}
}

func TestEncodePublicKeyToPEM(t *testing.T) {
	tests := []struct {
		name    string
		bitsize int
	}{
		{
			name:    "2048 Bit Size",
			bitsize: 2048,
		},
	}

	for _, test := range tests {
		p, err := GeneratePrivateKey(test.bitsize)
		if err != nil {
			t.Errorf("%s: Could not generate private key, got error: %s", test.name, err.Error())
		}
		pubPem, err := EncodePublicKeyToPEM(&p.PublicKey)
		if err != nil {
			t.Errorf("%s: Could not encode public key, got error: %s", test.name, err.Error())
		}
		pubFromPem, err := jwt.ParseRSAPublicKeyFromPEM(pubPem)
		if err != nil {
			t.Errorf("%s: Could not parse public key from PEM encoded block, got error: %s", test.name, err.Error())
		}
		if !pubEqual(pubFromPem, &p.PublicKey) {
			t.Errorf("%s: Public keys did not match", test.name)
		}
	}
}

func pubEqual(p *rsa.PublicKey, q *rsa.PublicKey) bool {
	if p.Size() == q.Size() && p.E == q.E && p.N == p.N {
		return true
	}
	return false
}
