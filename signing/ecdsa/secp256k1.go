package ecdsa

import (
	"crypto/sha256"
	"errors"
	"github.com/btcsuite/btcd/btcec"
)

var ES256k *SECP

func init () {
	ES256k = &SECP{}
}

type SECP struct {}

const name = "ES256k"

func (s *SECP) Alg() string {
	return name
}

func (s *SECP) Sign(msg []byte, key interface{}) ([]byte, error) {
	privateKey, ok := key.(*btcec.PrivateKey)
	if !ok {
		return nil, errors.New("not secp256k1 private key")
	}

	hash := sha256.Sum256(msg)

	sign, err := privateKey.Sign(hash[:])
	if err != nil {
		return nil, err
	}

	return sign.Serialize(), nil
}

func (s *SECP) Verify(msg []byte, signature []byte, key interface{}) bool {
	publicKey, ok := key.(*btcec.PublicKey)
	if !ok {
		return false
	}

	hash := sha256.Sum256(msg)

	sign, err := btcec.ParseSignature(signature, btcec.S256())
	if err != nil {
		return false
	}

	return sign.Verify(hash[:], publicKey)
}
