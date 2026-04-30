//go:build tinygo

/*
Copyright 2019 The Vitess Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package vttls

import (
	"errors"
	"strings"
)

// SslMode indicates the type of SSL mode to use.
type SslMode string

// Disabled disables SSL and connects over plain text.
const Disabled SslMode = "disabled"

// Preferred establishes an SSL connection if the server supports it.
const Preferred SslMode = "preferred"

// Required requires an SSL connection to the server.
const Required SslMode = "required"

// VerifyCA requires an SSL connection and validates the CA.
const VerifyCA SslMode = "verify_ca"

// VerifyIdentity requires an SSL connection and validates host identity.
const VerifyIdentity SslMode = "verify_identity"

// String returns the string representation.
func (mode *SslMode) String() string {
	return string(*mode)
}

// Set updates the value of the SslMode pointer.
func (mode *SslMode) Set(value string) error {
	parsedMode := SslMode(strings.ToLower(value))
	switch parsedMode {
	case "":
		*mode = Preferred
		return nil
	case Disabled, Preferred, Required, VerifyCA, VerifyIdentity:
		*mode = parsedMode
		return nil
	}
	return errors.New("invalid SSL mode")
}

// TLSVersionToNumber converts a text description of the TLS protocol
// to the internal Go number representation.
func TLSVersionToNumber(tlsVersion string) (uint16, error) {
	switch strings.ToLower(tlsVersion) {
	case "tlsv1.3":
		return 0x0304, nil
	case "", "tlsv1.2":
		return 0x0303, nil
	case "tlsv1.1":
		return 0x0302, nil
	case "tlsv1.0":
		return 0x0301, nil
	default:
		return 0x0303, errors.New("invalid TLS version")
	}
}

// ClientConfig is unsupported in TinyGo builds.
func ClientConfig(_ SslMode, _, _, _, _, _ string, _ uint16) (any, error) {
	return nil, errors.New("vttls client config is unsupported in TinyGo")
}

// ServerConfig is unsupported in TinyGo builds.
func ServerConfig(_, _, _, _, _ string, _ uint16) (any, error) {
	return nil, errors.New("vttls server config is unsupported in TinyGo")
}
