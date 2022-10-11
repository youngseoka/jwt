package signing

type Signer interface {
	Sign(msg []byte, key interface{}) (signature []byte, err error) // msg is json byte
	Verify(msg, signature []byte, key interface{}) bool
	Alg() string
}