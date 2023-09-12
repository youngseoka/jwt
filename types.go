package jwt

import (
	"errors"
)

const (
	TypeJWT = "JWT"
)

var (
	ErrIsgnature = errors.New(" not valid signature")
)
