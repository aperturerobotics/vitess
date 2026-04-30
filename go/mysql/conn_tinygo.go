//go:build tinygo

package mysql

import querypb "github.com/dolthub/vitess/go/vt/proto/query"

const DefaultConnBufferSize = 16 * 1024

// SingleStringElementFormatString is a template string that formats a single string element.
const SingleStringElementFormatString = "%s"

// Getter has a Get method.
type Getter interface {
	Get() *querypb.VTGateCallerID
}

// Conn is a tinygo placeholder for server/auth API signatures.
type Conn struct {
	Capabilities uint32
	ConnectionID uint32
	UserData     Getter
}

// PrepareData stores prepared statement metadata.
type PrepareData struct {
	StatementID uint32
	PrepareStmt string
	ParamsCount uint16
	ParamsType  []int32
	ColumnNames []string
	BindVars    map[string]*querypb.BindVariable
}

// ParsedQuery is a tinygo placeholder for parsed prepared statements.
type ParsedQuery any

// BoundQuery is a tinygo placeholder for bound prepared statements.
type BoundQuery any
