//go:build !tinygo

package mysql

func registerFilePosFlavor() {
	flavors[filePosFlavorID] = newFilePosFlavor
}
