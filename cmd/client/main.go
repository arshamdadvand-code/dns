// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package main

import (
	"fmt"
	"os"
	"strings"

	"masterdnsvpn-go/internal/config"
	"masterdnsvpn-go/internal/logger"
)

func main() {
	cfg, err := config.LoadClientConfig("client_config.toml")
	if err != nil {
		_, _ = os.Stderr.WriteString(fmt.Sprintf("Client startup failed: %v\n", err))
		os.Exit(1)
	}

	log := logger.New("MasterDnsVPN Go Client", cfg.LogLevel)
	log.Infof("[*] <green>Client Configuration Loaded</green>")
	log.Infof(
		"[*] <green>Protocol Type</green>: <cyan>%s</cyan>  |  <green>Encryption Method</green>: <cyan>%d</cyan>",
		cfg.ProtocolType,
		cfg.DataEncryptionMethod,
	)
	log.Infof(
		"[*] <green>Configured Domains</green>: <cyan>%s</cyan>",
		strings.Join(cfg.Domains, ", "),
	)
	log.Infof(
		"[*] <green>Loaded Resolvers</green>: <magenta>%d</magenta> unique IPs",
		len(cfg.Resolvers),
	)
	log.Infof("[*] <green>Client Bootstrap Ready</green>")
}
