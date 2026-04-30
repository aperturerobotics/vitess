//go:build !tinygo

package mysql

import (
	"crypto/tls"
	"crypto/x509"
	"net"
)

// GetTLSClientCerts gets TLS certificates.
func (c *Conn) GetTLSClientCerts() []*x509.Certificate {
	return getTLSClientCerts(c.Conn)
}

func getTLSClientCerts(conn net.Conn) []*x509.Certificate {
	if tlsConn, ok := conn.(*tls.Conn); ok {
		return tlsConn.ConnectionState().PeerCertificates
	}
	return nil
}

func isUnixSocket(listener net.Listener) bool {
	_, ok := listener.(*net.UnixListener)
	return ok
}

func tlsConnVersionString(conn net.Conn) string {
	if con, ok := conn.(*tls.Conn); ok {
		return tlsVersionToString(con.ConnectionState().Version)
	}
	return ""
}

func upgradeServerTLS(c *Conn, config *tls.Config) bool {
	conn := tls.Server(c.Conn, config)
	c.Conn = conn
	c.bufferedReader.Reset(conn)
	return true
}
