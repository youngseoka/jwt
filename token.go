package jwt

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/youngseoka/jwt/signing"
	"log"
	"strings"
	"time"
)

type Token struct {
	Header          header
	headerString    string
	Payload         interface{}
	payloadString   string
	Signature       signature
	signatureString string
}

func ParseCustomClaimToken(tokenString string, claim interface{}) (*Token, error) {
	splitted := strings.Split(tokenString, ".")
	if len(splitted) != 3 {
		return nil, ErrInvalidJWTString
	}

	h, err := parseHeaderString(splitted[0])
	if err != nil {
		return nil, ErrInvalidHeader
	}

	c, err := parseCustomClaim(splitted[1], claim)
	if err != nil {
		return nil, ErrInvalidPayload
	}

	s, err := base64.URLEncoding.WithPadding(base64.NoPadding).DecodeString(splitted[2])
	if err != nil {
		return nil, ErrInvalidSignature
	}

	return &Token{
		Header:          *h,
		headerString:    splitted[0],
		Payload:         c,
		payloadString:   splitted[1],
		Signature:       s,
		signatureString: splitted[2],
	}, nil
}

func ParseStandardClaimToken(tokenString string) (*Token, error) {
	splitted := strings.Split(tokenString, ".")
	if len(splitted) != 3 {
		return nil, ErrInvalidJWTString
	}

	h, err := parseHeaderString(splitted[0])
	if err != nil {
		return nil, ErrInvalidHeader
	}

	c, err := parseStandardClaim(splitted[1])
	if err != nil {
		return nil, ErrInvalidPayload
	}

	s, err := base64.URLEncoding.WithPadding(base64.NoPadding).DecodeString(splitted[2])
	if err != nil {
		return nil, ErrInvalidSignature
	}

	return &Token{
		Header:          *h,
		headerString:    splitted[0],
		Payload:         c,
		payloadString:   splitted[1],
		Signature:       s,
		signatureString: splitted[2],
	}, nil
}

func parseHeaderString(headerString string) (*header, error) {
	headerBytes, err := base64.URLEncoding.WithPadding(base64.NoPadding).DecodeString(headerString)
	if err != nil {
		log.Println(err)
		return nil, err
	}

	h := &header{}

	err = json.Unmarshal(headerBytes, h)
	if err != nil {
		log.Println("b")
		return nil, err
	}

	return h, nil
}

func parseCustomClaim(payloadString string, dst interface{}) (interface{}, error) {
	payloadBytes, err := base64.URLEncoding.WithPadding(base64.NoPadding).DecodeString(payloadString)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(payloadBytes, dst)
	if err != nil {
		return nil, err
	}

	return dst, nil
}

func parseStandardClaim(payloadString string) (*StandardClaims, error) {
	payloadBytes, err := base64.URLEncoding.WithPadding(base64.NoPadding).DecodeString(payloadString)
	if err != nil {
		return nil, err
	}

	stdClaimPayload := &StandardClaims{}
	err = json.Unmarshal(payloadBytes, stdClaimPayload)
	if err != nil {
		return nil, err
	}

	return stdClaimPayload, nil
}

func NewToken(payload interface{}, kid ...string) (*Token, error) {
	if payload == nil {
		return nil, errors.New("empty token")
	}

	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	payloadString := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(jsonPayload)

	token := &Token{
		Payload:       payload,
		payloadString: payloadString,
	}

	if kid != nil {
		token.Header = header{
			Kid: kid[0],
		}
	}
	return token, nil
}

func (t Token) Signed() bool {
	return t.Signature != nil // check signature is empty
}

func (t *Token) Sign(c signing.Signer, key interface{}) (string, error) {
	t.Header = header{
		Type: TypeJWT,
		Alg:  c.Alg(),
		Kid:  t.Header.Kid,
	}

	jsonHeader, err := json.Marshal(t.Header)
	if err != nil {
		return "", err
	}

	t.headerString = base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(jsonHeader)

	msg := t.headerString + "." + t.payloadString

	s, err := c.Sign([]byte(msg), key)
	if err != nil {
		return "", err
	}

	t.Signature = s

	signatureString := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(s)

	tokenString := msg + "." + signatureString

	return tokenString, nil
}

func (t *Token) Verify(c signing.Signer, key interface{}) bool {
	if !t.Signed() {
		return false
	}

	if t.Header.Alg != c.Alg() {
		return false
	}

	msg := t.headerString + "." + t.payloadString
	return c.Verify([]byte(msg), t.Signature, key)
}

// Valid method only validates expired, notBefore
// Validate other values by on your own
func (t *Token) Valid() (bool, error) {
	stdClaims, ok := t.Payload.(*StandardClaims)
	if !ok {
		return true, nil
	}

	if stdClaims.ExpiresAt != 0 {
		tm := time.Unix(stdClaims.ExpiresAt, 0)
		if tm.After(time.Now()) {
			return false, ErrExpired
		}
	}

	if stdClaims.NotBefore != 0 {
		tm := time.Unix(stdClaims.NotBefore, 0)
		if !tm.Before(time.Now()) {
			return false, ErrNotBefore
		}
	}

	return true, nil
}
