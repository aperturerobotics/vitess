//go:build !tinygo

package sqlparser

import (
	"context"
	"runtime/trace"
)

type parseRegion interface {
	End()
}

func startParseRegion(ctx context.Context, name string) parseRegion {
	return trace.StartRegion(ctx, name)
}
