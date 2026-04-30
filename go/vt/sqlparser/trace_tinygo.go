//go:build tinygo

package sqlparser

import "context"

type parseRegion struct{}

func (parseRegion) End() {}

func startParseRegion(_ context.Context, _ string) parseRegion {
	return parseRegion{}
}
