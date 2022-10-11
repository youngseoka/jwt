package ed25519

import (
	"crypto/ed25519"
	"errors"
	"strconv"
)

var ED25519 *Ed25519

func init() {
	ED25519 = &Ed25519{}
}

type Ed25519 struct {
}

const name = "ED25519"

func (e *Ed25519) Sign(msg []byte, key interface{}) ([]byte, error) {
	privateKey, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("not ed25519 private key")
	}

	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, errors.New("ed25519: bad private key length: " + strconv.Itoa(len(privateKey)))
	}

	return ed25519.Sign(privateKey, msg), nil
}

func (e *Ed25519) Verify(msg, signature []byte, key interface{}) bool {
	publicKey, ok := key.(ed25519.PublicKey)
	if !ok {
		return false
	}
	if len(publicKey) != ed25519.PublicKeySize {
		return false
	}

	return ed25519.Verify(publicKey, msg, signature)
}

func (e *Ed25519) Alg() string {
	return name
}
