//go:build tinygo

package mysql

import "errors"

// AuthServer validates users and passwords for server implementations.
type AuthServer interface {
	AuthMethods() []AuthMethod
	DefaultAuthMethodDescription() AuthMethodDescription
}

// AuthMethod describes a server authentication method.
type AuthMethod interface {
	Name() AuthMethodDescription
	HandleUser(conn *Conn, user string) bool
}

// CacheState is the result of a cache lookup during authentication.
type CacheState int

const (
	// AuthRejected is used when the cache knows the request can be rejected.
	AuthRejected CacheState = iota
	// AuthAccepted is used when the cache knows the request can be accepted.
	AuthAccepted
	// AuthNeedMoreData is used when the cache needs more data.
	AuthNeedMoreData
)

const DefaultCachingSha2PasswordHashIterations = 5

// NewSalt returns an unsupported TinyGo auth salt.
func NewSalt() ([]byte, error) {
	return nil, errors.New("mysql auth salt is not available in tinygo")
}

// SerializeCachingSha2PasswordAuthString is not available in TinyGo builds.
func SerializeCachingSha2PasswordAuthString(_ string, _ []byte, _ int) ([]byte, error) {
	return nil, errors.New("mysql auth serialization is not available in tinygo")
}
