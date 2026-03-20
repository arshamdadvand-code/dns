// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"masterdnsvpn-go/internal/client"
	"masterdnsvpn-go/internal/logger"
)

func exitWithStderrf(format string, args ...any) {
	_, _ = fmt.Fprintf(os.Stderr, format, args...)
	os.Exit(1)
}

func enabledClientListenerCount(localDNSEnabled bool, protocolType string) int {
	count := 0
	if localDNSEnabled {
		count++
	}
	if protocolType == "SOCKS5" || protocolType == "TCP" {
		count++
	}
	return count
}

func startClientListener(wg *sync.WaitGroup, errCh chan<- error, stop context.CancelFunc, label string, runCtx context.Context, run func(context.Context) error) {
	if wg == nil || run == nil {
		return
	}
	wg.Go(func() {
		if err := run(runCtx); err != nil {
			select {
			case errCh <- fmt.Errorf("%s failed: %w", label, err):
			default:
			}
			stop()
		}
	})
}

func main() {
	app, err := client.Bootstrap("client_config.toml")
	if err != nil {
		exitWithStderrf("Client startup failed: %v\n", err)
	}

	cfg := app.Config()
	log := app.Logger()
	if log != nil && log.Enabled(logger.LevelInfo) {
		log.Infof("\U0001F680 <green>Client Configuration Loaded</green>")
		log.Infof(
			"\U0001F680 <green>Client Mode, Protocol: <cyan>%s</cyan> Encryption: <cyan>%d</cyan></green>",
			cfg.ProtocolType,
			cfg.DataEncryptionMethod,
		)
		log.Infof(
			"\U00002696 <green>Resolver Balancing, Strategy: <cyan>%d</cyan></green>",
			cfg.ResolverBalancingStrategy,
		)
		log.Infof(
			"\U0001F310 <green>Configured Domains: <cyan>%d</cyan> (<cyan>%s</cyan>)</green>",
			len(cfg.Domains),
			formatDomains(cfg.Domains),
		)
		log.Infof(
			"\U0001F4E1 <green>Loaded Resolvers: <cyan>%d</cyan> endpoints.</green>",
			len(cfg.Resolvers),
		)

		if cfg.LocalDNSEnabled {
			log.Infof(
				"\U0001F9ED <green>Local DNS Listener Addr: <cyan>%s:%d</cyan></green>",
				cfg.LocalDNSIP,
				cfg.LocalDNSPort,
			)
		}

		if cfg.ProtocolType == "TCP" {
			log.Infof(
				"\U0001F50C <green>Local TCP Listener Addr: <cyan>%s:%d</cyan></green>",
				cfg.ListenIP,
				cfg.ListenPort,
			)
		} else if cfg.ProtocolType == "SOCKS5" {
			log.Infof(
				"\U0001F9E6 <green>Local SOCKS5 Listener Addr: <cyan>%s:%d</cyan></green>",
				cfg.ListenIP,
				cfg.ListenPort,
			)
			if cfg.SOCKS5Auth {
				log.Infof(
					"\U0001F510 <green>Local SOCKS5 Auth User: <cyan>%s</cyan></green>",
					cfg.SOCKS5User,
				)
				log.Infof(
					"\U0001F511 <green>Local SOCKS5 Auth Pass: <cyan>%s</cyan></green>",
					cfg.SOCKS5Pass,
				)
			}
		}

		log.Infof(
			"\U0001F5C2 <green>Connection Catalog <cyan>%d</cyan> domain-resolver pairs</green>",
			len(app.Connections()),
		)
		log.Infof(
			"\U00002705 <green>Active Connections</green> <cyan>%d</cyan>",
			app.Balancer().ValidCount(),
		)
	}

	var sessionCloseOnce sync.Once
	notifySessionClose := func() {
		sessionCloseOnce.Do(func() {
			app.BestEffortSessionClose(time.Second)
		})
	}

	runCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-runCtx.Done()
		notifySessionClose()
	}()

	readyCh := make(chan struct{})
	managerErrCh := make(chan error, 1)
	go func() {
		managerErrCh <- app.RunConnectionManager(runCtx, readyCh)
	}()

	select {
	case <-readyCh:
		if log != nil {
			log.Infof("\U0001F3AF <green>Client Bootstrap Ready</green>")
		}
	case err := <-managerErrCh:
		if err != nil {
			exitWithStderrf("Connection manager failed: %v\n", err)
		}
		return
	case <-runCtx.Done():
		notifySessionClose()
		return
	}

	if !cfg.LocalDNSEnabled && cfg.ProtocolType != "SOCKS5" && cfg.ProtocolType != "TCP" {
		notifySessionClose()
		stop()
		select {
		case err := <-managerErrCh:
			if err != nil {
				exitWithStderrf("Connection manager failed: %v\n", err)
			}
		default:
		}
		return
	}

	enabledListeners := enabledClientListenerCount(cfg.LocalDNSEnabled, cfg.ProtocolType)
	errCh := make(chan error, enabledListeners+1)
	var listenersWG sync.WaitGroup

	if cfg.LocalDNSEnabled {
		startClientListener(&listenersWG, errCh, stop, "local dns listener", runCtx, app.RunLocalDNSListener)
	}
	if cfg.ProtocolType == "SOCKS5" {
		startClientListener(&listenersWG, errCh, stop, "local socks5 listener", runCtx, app.RunLocalSOCKS5Listener)
	} else if cfg.ProtocolType == "TCP" {
		startClientListener(&listenersWG, errCh, stop, "local tcp listener", runCtx, app.RunLocalTCPListener)
	}

	listenersWG.Go(func() {
		if err := <-managerErrCh; err != nil {
			select {
			case errCh <- fmt.Errorf("connection manager failed: %w", err):
			default:
			}
			stop()
		}
	})

	listenersWG.Wait()
	notifySessionClose()
	select {
	case err := <-errCh:
		exitWithStderrf("%v\n", err)
	default:
	}
}

func formatDomains(s []string) string {
	if len(s) == 0 {
		return "<none>"
	}
	if len(s) == 1 {
		return s[0]
	}
	if len(s) <= 5 {
		return strings.Join(s, ", ")
	}

	var builder strings.Builder
	for i := range 5 {
		if i != 0 {
			builder.WriteString(", ")
		}
		builder.WriteString(s[i])
	}
	builder.WriteString(", ...")
	return builder.String()
}
