//go:build tools
// +build tools

package unused

// _ imports goyacc
import _ "golang.org/x/tools/cmd/goyacc"

// _ imports common with the Makefile and tools
import _ "github.com/aperturerobotics/common"
