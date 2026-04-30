//go:build tinygo

package mysql

import (
	"context"

	"github.com/dolthub/vitess/go/sqltypes"
	querypb "github.com/dolthub/vitess/go/vt/proto/query"
)

const (
	DefaultServerVersion = "8.0.33"
	queryTimingKey       = "Query"
)

// Handler receives server-side MySQL command callbacks.
type Handler interface {
	NewConnection(c *Conn)
	ConnectionClosed(c *Conn)
	ConnectionAuthenticated(*Conn) error
	ConnectionAborted(c *Conn, reason string) error
	ComInitDB(c *Conn, schemaName string) error
	ComQuery(ctx context.Context, c *Conn, query string, callback ResultSpoolFn) error
	ComMultiQuery(ctx context.Context, c *Conn, query string, callback ResultSpoolFn) (string, error)
	ComPrepare(ctx context.Context, c *Conn, query string, prepare *PrepareData) ([]*querypb.Field, error)
	ComStmtExecute(ctx context.Context, c *Conn, prepare *PrepareData, callback func(*sqltypes.Result) error) error
	WarningCount(c *Conn) uint16
	ComResetConnection(c *Conn) error
}

// ResultSpoolFn handles rows returned by a query.
type ResultSpoolFn func(res *sqltypes.Result, more bool) error

// BinlogReplicaHandler receives binlog replication server commands.
type BinlogReplicaHandler interface {
	ComRegisterReplica(c *Conn, replicaHost string, replicaPort uint16, replicaUser string, replicaPassword string) error
	ComBinlogDumpGTID(c *Conn, logFile string, logPos uint64, gtidSet GTIDSet) error
}

// Listener is a minimal TinyGo server placeholder.
type Listener struct{}

func (l *Listener) isShutdown() bool {
	return true
}
