//go:build tinygo

package mysql

func upgradeServerTLS(_ *Conn, _ any) bool {
	return false
}
