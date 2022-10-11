package jwt

import (
	"errors"
)

const (
	TypeJWT = "JWT"
)

var (
	ErrInvalidJWTString = errors.New("not valid JWT token string")
	ErrInvalidHeader    = errors.New("not valid header")
	ErrInvalidPayload   = errors.New("not valid payload")
)

type header struct {
	Type string `json:"type"`
	Alg  string `json:"alg"`
	Kid  string `json:"kid,omitempty"`
}

// Registered claim
type StandardClaims struct {
	Audience  string `json:"aud,omitempty"`
	ExpiresAt int64  `json:"exp,omitempty"`
	Id        string `json:"jti,omitempty"`
	IssuedAt  int64  `json:"iat,omitempty"`
	Issuer    string `json:"iss,omitempty"`
	NotBefore int64  `json:"nbf,omitempty"`
	Subject   string `json:"sub,omitempty"`
}

var (
	ErrExpired   = errors.New("token expired")
	ErrNotBefore = errors.New("token not yet valid")
)

type signature []byte

var (
	ErrInvalidSignature = errors.New(" not valid signature")
)
