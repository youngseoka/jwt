package jwt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	ecdsa2 "github.com/youngseoka/jwt/signing/ecdsa"
	"strings"
	"testing"

	_ "crypto/sha256"
)

const testToken = "eyJ0eXBlIjoiSldUIiwiYWxnIjoiRVMyNTYifQ.eyJ2YWx1ZSI6InRlc3QiLCJpc3MiOiJ3aGl0ZWJsb2NrIn0.4fRZXscZ3Znd5PLIuxcuGttQqLRgEz964nhazSXFXHHaq0ydnE7zJAr1BHSXyf1hNGJ9_rJo44ocYmQKAF9QVw"

type testClaim struct {
	Value string `json:"value"`
	StandardClaims
}

func TestNewToken(t *testing.T) {
	_, err := NewToken(nil)
	if err == nil {
		t.Log("expected err but no error returned")
		t.Fail()
	}

	c := &testClaim{
		Value: "test",
		StandardClaims: StandardClaims{
			Issuer: "whiteblock",
		},
	}

	token, err := NewToken(c)
	if err != nil {
		t.Logf("expected no error but error accured: %v\n", err)
		t.Fatal()
	}

	if token.Payload == nil {
		t.Log("payload empty")
		t.Fatal()
	}

	if token.Payload != c {
		t.Log("payload not match")
		t.Fatal()
	}

	if token.payloadString == "" {
		t.Logf("empty payloadString")
		t.Fatal()
	}

	payloadByte, _ := json.Marshal(token.Payload)

	payloadString := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(payloadByte)
	if payloadString != token.payloadString {
		t.Logf("payloadString not match. expected %v but got %v", payloadString, token.payloadString)
		t.Fail()
	}
}

func TestToken_Sign(t *testing.T) {
	c := &testClaim{
		Value: "test",
		StandardClaims: StandardClaims{
			Issuer: "whiteblock",
		},
	}

	token, err := NewToken(c)
	if err != nil {
		t.Logf("expected no error but error accured: %v\n", err)
		t.Fatal()
	}

	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	tokenString, err := token.Sign(ecdsa2.ES256, privKey)
	if err != nil {
		t.Logf("error accured during sign: %v\n", err)
		t.Fatal()
	}

	if token.Header.Alg != ecdsa2.ES256.Alg() {
		t.Logf("alg not match. expected %v but got %v\n", token.Header.Alg, ecdsa2.ES256.Alg())
		t.Fail()
	}

	if token.Header.Type != TypeJWT {
		t.Log("header type must JWT")
		t.Fail()
	}

	if token.headerString == "" {
		t.Log("headerString is empty")
		t.Fail()
	}

	if token.Signature == nil {
		t.Log("signature is empty")
		t.Fail()
	}

	splitted := strings.Split(tokenString, ".")
	if len(splitted) != 3 {
		t.Fatalf("jwt must includes 3 parts. got %v parts\n", len(splitted)+1)
	}

	if strings.Contains(tokenString, "=") {
		t.Fatal("tokenString must be URL safe. but found = in string")
	}
}

func TestParseCustomClaimToken(t *testing.T) {
	claim := &testClaim{}

	tokenString := "eyJ0eXBlIjoiSldUIiwiYWxnIjoiRVMyNTYifQ.eyJ2YWx1ZSI6InRlc3QiLCJpc3MiOiJ3aGl0ZWJsb2NrIn0.dYVhJm94CDNfKvpdKXSa-aXZPM7Xr3rgu2ArU9QaEkkGPVIZwWElMtSa-RRFluSIF7LmTViaPvHBTOuXIxSQHw"

	_, err := ParseCustomClaimToken(tokenString, claim)
	if err != nil {
		t.Error(err)
	}
}
