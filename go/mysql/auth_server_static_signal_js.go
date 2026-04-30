//go:build js && !tinygo

package mysql

import "time"

func (a *AuthServerStatic) installSignalHandlers() {
	if a.file == "" || a.reloadInterval <= 0 {
		return
	}

	a.ticker = time.NewTicker(a.reloadInterval)
	go func() {
		for range a.ticker.C {
			a.reload()
		}
	}()
}

func (a *AuthServerStatic) close() {
	if a.ticker != nil {
		a.ticker.Stop()
	}
}
