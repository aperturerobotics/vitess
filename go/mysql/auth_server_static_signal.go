//go:build !js && !tinygo

package mysql

import (
	"os"
	"os/signal"
	"syscall"
	"time"
)

func (a *AuthServerStatic) installSignalHandlers() {
	if a.file == "" {
		return
	}

	a.sigChan = make(chan os.Signal, 1)
	signal.Notify(a.sigChan, syscall.SIGHUP)
	go func() {
		for range a.sigChan {
			a.reload()
		}
	}()

	if a.reloadInterval > 0 {
		a.ticker = time.NewTicker(a.reloadInterval)
		go func() {
			for range a.ticker.C {
				a.sigChan <- syscall.SIGHUP
			}
		}()
	}
}

func (a *AuthServerStatic) close() {
	if a.ticker != nil {
		a.ticker.Stop()
	}
	if a.sigChan != nil {
		signal.Stop(a.sigChan)
	}
}
