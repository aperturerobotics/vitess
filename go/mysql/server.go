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

package mysql

import (
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/dolthub/vitess/go/sqltypes"
	"github.com/dolthub/vitess/go/stats"
	"github.com/dolthub/vitess/go/sync2"
	"github.com/dolthub/vitess/go/tb"
	"github.com/dolthub/vitess/go/vt/log"
	querypb "github.com/dolthub/vitess/go/vt/proto/query"
	"github.com/dolthub/vitess/go/vt/proto/vtrpc"
	"github.com/dolthub/vitess/go/vt/sqlparser"
	"github.com/dolthub/vitess/go/vt/vterrors"
)

const (
	// DefaultServerVersion is the default server version we're sending to the client.
	// Can be changed.
	DefaultServerVersion = "8.0.33"

	// timing metric keys
	connectTimingKey = "Connect"
	queryTimingKey   = "Query"
)

var (
	// Metrics
	timings    = stats.NewTimings("MysqlServerTimings", "MySQL server timings", "operation")
	connAccept = stats.NewCounter("MysqlServerConnAccepted", "Connections accepted by MySQL server")
	connSlow   = stats.NewCounter("MysqlServerConnSlow", "Connections that took more than the configured mysql_slow_connect_warn_threshold to establish")
)

// A Handler is an interface used by Listener to send queries.
// The implementation of this interface may store data in the ClientData
// field of the Connection for its own purposes.
//
// For a given Connection, all these methods are serialized. It means
// only one of these methods will be called concurrently for a given
// Connection. So access to the Connection ClientData does not need to
// be protected by a mutex.
//
// However, each connection is using one go routine, so multiple
// Connection objects can call these concurrently, for different Connections.
type Handler interface {
	// NewConnection is called when a connection is created.
	// It is not established yet. The handler can decide to
	// set StatusFlags that will be returned by the handshake methods.
	// In particular, ServerStatusAutocommit might be set.
	NewConnection(c *Conn)

	// ConnectionClosed is called when a connection is closed.
	ConnectionClosed(c *Conn)

	// ConnectionAborted is called when a new connection cannot be fully established. For
	// example, if a client connects to the server, but fails authentication, or can't
	// negotiate an authentication handshake, this method will be called to let integrators
	// know about the failed connection attempt.
	ConnectionAborted(c *Conn, reason string) error

	// ComInitDB is called once at the beginning to set db name,
	// and subsequently for every ComInitDB event.
	ComInitDB(c *Conn, schemaName string) error

	// ComQuery is called when a connection receives a query.
	// Note the contents of the query slice may change after
	// the first call to callback. So the Handler should not
	// hang on to the byte slice.
	ComQuery(ctx context.Context, c *Conn, query string, callback ResultSpoolFn) error

	// ComMultiQuery is called when a connection receives a query and the
	// client supports MULTI_STATEMENT. It should process the first
	// statement in |query| and return the remainder. It will be called
	// multiple times until the remainder is |""|.
	ComMultiQuery(ctx context.Context, c *Conn, query string, callback ResultSpoolFn) (string, error)

	// ComPrepare is called when a connection receives a prepared
	// statement query.
	ComPrepare(ctx context.Context, c *Conn, query string, prepare *PrepareData) ([]*querypb.Field, error)

	// ComStmtExecute is called when a connection receives a statement
	// execute query.
	ComStmtExecute(ctx context.Context, c *Conn, prepare *PrepareData, callback func(*sqltypes.Result) error) error

	// WarningCount is called at the end of each query to obtain
	// the value to be returned to the client in the EOF packet.
	// Note that this will be called either in the context of the
	// ComQuery callback if the result does not contain any fields,
	// or after the last ComQuery call completes.
	WarningCount(c *Conn) uint16

	// ComResetConnection is called when a connection receives a COM_RESET_CONNECTION signal.
	// This is used to reset the session state (e.g. clearing user vars, resetting session vars, releasing
	// locks, releasing cached prepared statements, etc). One of the primary use cases for COM_RESET_CONNECTION
	// is to reset a pooled connection's session state so that it can be safely returned to the connection pool
	// and given to another application process to reuse.
	ComResetConnection(c *Conn) error

	// ParserOptionsForConnection returns any parser options that should be used for the given connection. For
	// example, if the connection has enabled ANSI_QUOTES or ANSI SQL_MODE, then the parser needs to know that
	// in order to parse queries correctly. This is primarily needed when a prepared statement request comes in,
	// and the Vitess layer needs to parse the query to identify the query parameters so that the correct response
	// packets can be sent.
	ParserOptionsForConnection(c *Conn) (sqlparser.ParserOptions, error)
}

// BinlogReplicaHandler is an extension to the Handler interface, to add support for binlog replication server commands.
type BinlogReplicaHandler interface {
	// ComRegisterReplica is called when a connection receives a ComRegisterReplica request
	ComRegisterReplica(c *Conn, replicaHost string, replicaPort uint16, replicaUser string, replicaPassword string) error

	// ComBinlogDumpGTID is called when a connection receives a ComBinlogDumpGTID request
	ComBinlogDumpGTID(c *Conn, logFile string, logPos uint64, gtidSet GTIDSet) error
}

// ResultSpoolFn is the callback function used by ComQuery and related functions to handle rows returned by a query
type ResultSpoolFn func(res *sqltypes.Result, more bool) error

// ExtendedHandler is an extension to Handler to support additional protocols on top of MySQL.
type ExtendedHandler interface {
	// ComParsedQuery is called when a connection receives a query that has already been parsed. Note the contents
	// of the query slice may change after the first call to callback. So the Handler should not hang on to the byte
	// slice.
	ComParsedQuery(ctx context.Context, c *Conn, query string, parsed sqlparser.Statement, callback ResultSpoolFn) error

	// ComPrepareParsed is called when a connection receives a prepared statement query that has already been parsed.
	ComPrepareParsed(ctx context.Context, c *Conn, query string, parsed sqlparser.Statement, prepare *PrepareData) (ParsedQuery, []*querypb.Field, error)

	// ComBind is called when a connection receives a request to bind a prepared statement to a set of values.
	ComBind(ctx context.Context, c *Conn, query string, parsedQuery ParsedQuery, prepare *PrepareData) (BoundQuery, []*querypb.Field, error)

	// ComExecuteBound is called when a connection receives a request to execute a prepared statement that has already
	// bound to a set of values.
	ComExecuteBound(ctx context.Context, c *Conn, query string, boundQuery BoundQuery, callback ResultSpoolFn) error
}

// ParsedQuery is a marker type for communication between the ExtendedHandler interface and integrators, representing a
// query plan that can be examined or executed
type ParsedQuery any

// BoundQuery is a marker type for communication between the ExtendedHandler interface and integrators, representing a
// query plan that has been bound to a set of values
type BoundQuery any

// Listener is the MySQL server protocol listener.
type Listener struct {
	// Construction parameters, set by NewListener.

	// authServer is the AuthServer object to use for authentication.
	authServer AuthServer

	// handler is the data handler.
	handler Handler

	// The following parameters are read by multiple connection go
	// routines.  They are not protected by a mutex, so they
	// should be set after NewListener, and not changed while
	// Accept is running.

	// ServerVersion is the version we will advertise.
	ServerVersion string

	// SlowConnectWarnThreshold if non-zero specifies an amount of time
	// beyond which a warning is logged to identify the slow connection
	SlowConnectWarnThreshold sync2.AtomicDuration

	// RequireSecureTransport configures the server to reject connections from insecure clients
	RequireSecureTransport bool
}

// NewListener creates a new Listener.
func NewListener(authServer AuthServer, handler Handler) (*Listener, error) {
	return &Listener{
		authServer:    authServer,
		handler:       handler,
		ServerVersion: DefaultServerVersion,
	}, nil
}

// HandleConn handles a connection.
// FIXME(alainjobart) handle per-connection logs in a way that makes sense.
func (l *Listener) HandleConn(ctx context.Context, conn net.Conn, connectionID uint32, acceptTime time.Time) {
	l.handle(ctx, conn, connectionID, acceptTime)
}

// handle is called in a go routine for each client connection.
// FIXME(alainjobart) handle per-connection logs in a way that makes sense.
func (l *Listener) handle(ctx context.Context, conn net.Conn, connectionID uint32, acceptTime time.Time) {
	c := newServerConn(conn, l)
	c.ConnectionID = connectionID

	// Catch panics, and close the connection in any case.
	defer func() {
		if x := recover(); x != nil {
			log.Errorf("mysql_server caught panic:\n%v\n%s", x, tb.Stack(4))
		}

		// We call flush here in case there's a premature return after
		// startWriterBuffering is called
		c.flush(ctx)

		conn.Close()
	}()

	// Tell the handler about the connection coming and going.
	l.handler.NewConnection(c)
	defer l.handler.ConnectionClosed(c)
	defer c.discardCursor()

	// First build and send the server handshake packet.
	salt, err := c.writeHandshakeV10(l.ServerVersion, l.authServer)
	if err != nil {
		if err != io.EOF {
			l.handleConnectionError(c, fmt.Sprintf("Cannot send HandshakeV10 packet: %v", err))
		}
		return
	}

	// Wait for the client response. This has to be a direct read,
	// so we don't buffer the TLS negotiation packets.
	response, err := c.readEphemeralPacketDirect(ctx)
	if err != nil {
		// Don't log EOF errors. They cause too much spam, same as main read loop.
		if err != io.EOF {
			l.handleConnectionWarning(c, fmt.Sprintf(
				"Cannot read client handshake response from %s: %v, "+
					"it may not be a valid MySQL client", c, err))
		}
		return
	}
	user, authMethod, authResponse, err := l.parseClientHandshakePacket(c, true, response)
	if err != nil {
		l.handleConnectionError(c, fmt.Sprintf(
			"Cannot parse client handshake response from %s: %v", c, err))
		return
	}

	c.recycleReadPacket()

	if c.Capabilities&CapabilityClientSSL > 0 {
		// SSL was enabled. We need to re-read the auth packet.
		response, err = c.readEphemeralPacket(ctx)
		if err != nil {
			l.handleConnectionError(c, fmt.Sprintf(
				"Cannot read post-SSL client handshake response from %s: %v", c, err))
			return
		}

		// Returns copies of the data, so we can recycle the buffer.
		user, authMethod, authResponse, err = l.parseClientHandshakePacket(c, false, response)
		if err != nil {
			l.handleConnectionError(c, fmt.Sprintf(
				"Cannot parse post-SSL client handshake response from %s: %v", c, err))
			return
		}
		c.recycleReadPacket()
	} else {
		/*
			if l.RequireSecureTransport {
				c.writeErrorPacketFromError(vterrors.Errorf(vtrpc.Code_UNAVAILABLE, "server does not allow insecure connections, client must use SSL/TLS"))
			}
		*/
	}

	// See what auth method the AuthServer wants to use for that user.
	authServerMethod, err := l.authServer.AuthMethod(user, conn.RemoteAddr().String())
	if err != nil {
		l.handleConnectionError(c, "auth server failed to determine auth method")
		c.writeErrorPacketFromError(err)
		return
	}

	// Compare with what the client sent back.
	switch {
	case authServerMethod == MysqlNativePassword && authMethod == MysqlNativePassword:
		// Both server and client want to use MysqlNativePassword:
		// the negotiation can be completed right away, using the
		// ValidateHash() method.
		userData, err := l.authServer.ValidateHash(salt, user, authResponse, conn.RemoteAddr())
		if err != nil {
			l.handleConnectionWarning(c, fmt.Sprintf(
				"Error authenticating user using MySQL native password: %v", err))
			c.writeErrorPacketFromError(err)
			return
		}
		c.User = user
		c.UserData = userData

	case authServerMethod == MysqlNativePassword:
		// The server really wants to use MysqlNativePassword,
		// but the client returned a result for something else.

		salt, err := l.authServer.Salt()
		if err != nil {
			return
		}
		//lint:ignore SA4006 This line is required because the binary protocol requires padding with 0
		data := make([]byte, 21)
		data = append(salt, byte(0x00))
		if err := c.writeAuthSwitchRequest(MysqlNativePassword, data); err != nil {
			l.handleConnectionError(c, fmt.Sprintf("Error writing auth switch packet for %s: %v", c, err))
			return
		}

		response, err := c.readEphemeralPacket(ctx)
		if err != nil {
			l.handleConnectionError(c, fmt.Sprintf(
				"Error reading auth switch response for %s: %v", c, err))
			return
		}
		c.recycleReadPacket()

		userData, err := l.authServer.ValidateHash(salt, user, response, conn.RemoteAddr())
		if err != nil {
			l.handleConnectionWarning(c, fmt.Sprintf(
				"Error authenticating user using MySQL native password: %v", err))
			c.writeErrorPacketFromError(err)
			return
		}
		c.User = user
		c.UserData = userData

	default:
		// The server wants to use something else, re-negotiate.

		// Switch our auth method to what the server wants.
		// Dialog plugin expects an AskPassword prompt.
		var data []byte
		if authServerMethod == MysqlDialog {
			data = authServerDialogSwitchData()
		}
		if err := c.writeAuthSwitchRequest(authServerMethod, data); err != nil {
			l.handleConnectionError(c, fmt.Sprintf(
				"Error writing auth switch packet for %s: %v", c, err))
			return
		}

		// Then hand over the rest of the negotiation to the
		// auth server.
		userData, err := l.authServer.Negotiate(c, user, conn.RemoteAddr())
		if err != nil {
			l.handleConnectionWarning(c, fmt.Sprintf(
				"Unable to negotiate authentication: %v", err))
			c.writeErrorPacketFromError(err)
			return
		}
		c.User = user
		c.UserData = userData
	}

	// Set db name.
	if err = l.handler.ComInitDB(c, c.schemaName); err != nil {
		log.Errorf("failed to set the database %s: %v", c, err)

		c.writeErrorPacketFromError(err)
		return
	}

	// Negotiation worked, send OK packet.
	if err := c.writeOKPacket(0, 0, c.StatusFlags, 0); err != nil {
		log.Errorf("Cannot write OK packet to %s: %v", c, err)
		return
	}

	// Record how long we took to establish the connection
	timings.Record(connectTimingKey, acceptTime)

	// Log a warning if it took too long to connect
	connectTime := time.Since(acceptTime)
	if threshold := l.SlowConnectWarnThreshold.Get(); threshold != 0 && connectTime > threshold {
		connSlow.Add(1)
		log.Warningf("Slow connection from %s: %v", c, connectTime)
	}

	for {
		err := c.handleNextCommand(ctx, l.handler)
		if err != nil {
			return
		}
	}
}

// handleConnectionError logs |reason| as an error and notifies the handler that a connection has been aborted.
func (l *Listener) handleConnectionError(c *Conn, reason string) {
	log.Error(reason)
	if err := l.handler.ConnectionAborted(c, reason); err != nil {
		log.Errorf("unable to report connection aborted to handler: %s", err)
	}
}

// handleConnectionWarning logs |reason| as a warning and notifies the handler that a connection has been aborted.
func (l *Listener) handleConnectionWarning(c *Conn, reason string) {
	log.Warning(reason)
	if err := l.handler.ConnectionAborted(c, reason); err != nil {
		log.Errorf("unable to report connection aborted to handler: %s", err)
	}
}

// writeHandshakeV10 writes the Initial Handshake Packet, server side.
// It returns the salt data.
func (c *Conn) writeHandshakeV10(serverVersion string, authServer AuthServer) ([]byte, error) {
	capabilities := CapabilityClientLongPassword |
		CapabilityClientLongFlag |
		CapabilityClientConnectWithDB |
		CapabilityClientProtocol41 |
		CapabilityClientTransactions |
		CapabilityClientSecureConnection |
		CapabilityClientMultiStatements |
		CapabilityClientMultiResults |
		CapabilityClientPluginAuth |
		CapabilityClientPluginAuthLenencClientData |
		CapabilityClientDeprecateEOF |
		CapabilityClientConnAttr |
		CapabilityClientFoundRows |
		CapabilityClientLocalFiles
	/*
		if enableTLS {
			capabilities |= CapabilityClientSSL
		}
	*/

	length :=
		1 + // protocol version
			lenNullString(serverVersion) +
			4 + // connection ID
			8 + // first part of salt data
			1 + // filler byte
			2 + // capability flags (lower 2 bytes)
			1 + // character set
			2 + // status flag
			2 + // capability flags (upper 2 bytes)
			1 + // length of auth plugin data
			10 + // reserved (0)
			13 + // auth-plugin-data
			lenNullString(MysqlNativePassword) // auth-plugin-name

	data := c.startEphemeralPacket(length)
	pos := 0

	// Protocol version.
	pos = writeByte(data, pos, protocolVersion)

	// Copy server version.
	pos = writeNullString(data, pos, serverVersion)

	// Add connectionID in.
	pos = writeUint32(data, pos, c.ConnectionID)

	// Generate the salt, put 8 bytes in.
	salt, err := authServer.Salt()
	if err != nil {
		return nil, err
	}

	pos += copy(data[pos:], salt[:8])

	// One filler byte, always 0.
	pos = writeByte(data, pos, 0)

	// Lower part of the capability flags.
	pos = writeUint16(data, pos, uint16(capabilities))

	// Character set.
	pos = writeByte(data, pos, CharacterSetUtf8)

	// Status flag.
	pos = writeUint16(data, pos, c.StatusFlags)

	// Upper part of the capability flags.
	pos = writeUint16(data, pos, uint16(capabilities>>16))

	// Length of auth plugin data.
	// Always 21 (8 + 13).
	pos = writeByte(data, pos, 21)

	// Reserved 10 bytes: all 0
	pos = writeZeroes(data, pos, 10)

	// Second part of auth plugin data.
	pos += copy(data[pos:], salt[8:])
	data[pos] = 0
	pos++

	// Copy authPluginName. We always start with mysql_native_password.
	pos = writeNullString(data, pos, MysqlNativePassword)

	// Sanity check.
	if pos != len(data) {
		return nil, vterrors.Errorf(vtrpc.Code_INTERNAL, "error building Handshake packet: got %v bytes expected %v", pos, len(data))
	}

	if err := c.writeEphemeralPacket(); err != nil {
		if strings.HasSuffix(err.Error(), "write: connection reset by peer") {
			return nil, io.EOF
		}
		if strings.HasSuffix(err.Error(), "write: broken pipe") {
			return nil, io.EOF
		}
		return nil, err
	}

	return salt, nil
}

// parseClientHandshakePacket parses the handshake sent by the client.
// Returns the username, auth method, auth data, error.
// The original data is not pointed at, and can be freed.
func (l *Listener) parseClientHandshakePacket(c *Conn, firstTime bool, data []byte) (string, string, []byte, error) {
	pos := 0

	// Client flags, 4 bytes.
	clientFlags, pos, ok := readUint32(data, pos)
	if !ok {
		return "", "", nil, vterrors.Errorf(vtrpc.Code_INTERNAL, "parseClientHandshakePacket: can't read client flags")
	}
	if clientFlags&CapabilityClientProtocol41 == 0 {
		return "", "", nil, vterrors.Errorf(vtrpc.Code_INTERNAL, "parseClientHandshakePacket: only support protocol 4.1")
	}

	// Remember a subset of the capabilities, so we can use them
	// later in the protocol. If we re-received the handshake packet
	// after SSL negotiation, do not overwrite capabilities.
	if firstTime {
		c.Capabilities = clientFlags & (CapabilityClientDeprecateEOF | CapabilityClientFoundRows)
	}

	// set connection capability for executing multi statements
	if clientFlags&CapabilityClientMultiStatements > 0 {
		c.Capabilities |= CapabilityClientMultiStatements
	}

	// Max packet size. Don't do anything with this now.
	// See doc.go for more information.
	_, pos, ok = readUint32(data, pos)
	if !ok {
		return "", "", nil, vterrors.Errorf(vtrpc.Code_INTERNAL, "parseClientHandshakePacket: can't read maxPacketSize")
	}

	// Character set. Need to handle it.
	characterSet, pos, ok := readByte(data, pos)
	if !ok {
		return "", "", nil, vterrors.Errorf(vtrpc.Code_INTERNAL, "parseClientHandshakePacket: can't read characterSet")
	}
	c.CharacterSet = characterSet

	// 23x reserved zero bytes.
	pos += 23

	// username
	username, pos, ok := readNullString(data, pos)
	if !ok {
		return "", "", nil, vterrors.Errorf(vtrpc.Code_INTERNAL, "parseClientHandshakePacket: can't read username")
	}

	// auth-response can have three forms.
	var authResponse []byte
	if clientFlags&CapabilityClientPluginAuthLenencClientData != 0 {
		var l uint64
		l, pos, ok = readLenEncInt(data, pos)
		if !ok {
			return "", "", nil, vterrors.Errorf(vtrpc.Code_INTERNAL, "parseClientHandshakePacket: can't read auth-response variable length")
		}
		authResponse, pos, ok = readBytesCopy(data, pos, int(l))
		if !ok {
			return "", "", nil, vterrors.Errorf(vtrpc.Code_INTERNAL, "parseClientHandshakePacket: can't read auth-response")
		}

	} else if clientFlags&CapabilityClientSecureConnection != 0 {
		var l byte
		l, pos, ok = readByte(data, pos)
		if !ok {
			return "", "", nil, vterrors.Errorf(vtrpc.Code_INTERNAL, "parseClientHandshakePacket: can't read auth-response length")
		}

		authResponse, pos, ok = readBytesCopy(data, pos, int(l))
		if !ok {
			return "", "", nil, vterrors.Errorf(vtrpc.Code_INTERNAL, "parseClientHandshakePacket: can't read auth-response")
		}
	} else {
		a := ""
		a, pos, ok = readNullString(data, pos)
		if !ok {
			return "", "", nil, vterrors.Errorf(vtrpc.Code_INTERNAL, "parseClientHandshakePacket: can't read auth-response")
		}
		authResponse = []byte(a)
	}

	// db name.
	if clientFlags&CapabilityClientConnectWithDB != 0 {
		dbname := ""
		dbname, pos, ok = readNullString(data, pos)
		if !ok {
			return "", "", nil, vterrors.Errorf(vtrpc.Code_INTERNAL, "parseClientHandshakePacket: can't read dbname")
		}
		c.schemaName = dbname
	}

	// authMethod (with default)
	authMethod := MysqlNativePassword
	if clientFlags&CapabilityClientPluginAuth != 0 {
		authMethod, pos, ok = readNullString(data, pos)
		if !ok {
			return "", "", nil, vterrors.Errorf(vtrpc.Code_INTERNAL, "parseClientHandshakePacket: can't read authMethod")
		}
	}

	// The JDBC driver sometimes sends an empty string as the auth method when it wants to use mysql_native_password
	if authMethod == "" {
		authMethod = MysqlNativePassword
	}

	// Decode connection attributes send by the client
	if clientFlags&CapabilityClientConnAttr != 0 {
		if _, _, err := parseConnAttrs(data, pos); err != nil {
			log.Warningf("Decode connection attributes send by the client: %v", err)
		}
	}

	return username, authMethod, authResponse, nil
}

func parseConnAttrs(data []byte, pos int) (map[string]string, int, error) {
	var attrLen uint64

	attrLen, pos, ok := readLenEncInt(data, pos)
	if !ok {
		return nil, 0, vterrors.Errorf(vtrpc.Code_INTERNAL, "parseClientHandshakePacket: can't read connection attributes variable length")
	}

	var attrLenRead uint64

	attrs := make(map[string]string)

	for attrLenRead < attrLen {
		var keyLen byte
		keyLen, pos, ok = readByte(data, pos)
		if !ok {
			return nil, 0, vterrors.Errorf(vtrpc.Code_INTERNAL, "parseClientHandshakePacket: can't read connection attribute key length")
		}
		attrLenRead += uint64(keyLen) + 1

		var connAttrKey []byte
		connAttrKey, pos, ok = readBytesCopy(data, pos, int(keyLen))
		if !ok {
			return nil, 0, vterrors.Errorf(vtrpc.Code_INTERNAL, "parseClientHandshakePacket: can't read connection attribute key")
		}

		var valLen byte
		valLen, pos, ok = readByte(data, pos)
		if !ok {
			return nil, 0, vterrors.Errorf(vtrpc.Code_INTERNAL, "parseClientHandshakePacket: can't read connection attribute value length")
		}
		attrLenRead += uint64(valLen) + 1

		var connAttrVal []byte
		connAttrVal, pos, ok = readBytesCopy(data, pos, int(valLen))
		if !ok {
			return nil, 0, vterrors.Errorf(vtrpc.Code_INTERNAL, "parseClientHandshakePacket: can't read connection attribute value")
		}

		attrs[string(connAttrKey[:])] = string(connAttrVal[:])
	}

	return attrs, pos, nil

}

// writeAuthSwitchRequest writes an auth switch request packet.
func (c *Conn) writeAuthSwitchRequest(pluginName string, pluginData []byte) error {
	length := 1 + // AuthSwitchRequestPacket
		len(pluginName) + 1 + // 0-terminated pluginName
		len(pluginData)

	data := c.startEphemeralPacket(length)
	pos := 0

	// Packet header.
	pos = writeByte(data, pos, AuthSwitchRequestPacket)

	// Copy server version.
	pos = writeNullString(data, pos, pluginName)

	// Copy auth data.
	pos += copy(data[pos:], pluginData)

	// Sanity check.
	if pos != len(data) {
		return vterrors.Errorf(vtrpc.Code_INTERNAL, "error building AuthSwitchRequestPacket packet: got %v bytes expected %v", pos, len(data))
	}
	return c.writeEphemeralPacket()
}
