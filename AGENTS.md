# MasterDnsVPN Onboarding Notes

## Project Summary

- `MasterDnsVPN` is a Go-based DNS tunnel / VPN-style transport.
- Server listens on DNS, usually UDP `53`.
- Client exposes a local SOCKS5 proxy, usually `127.0.0.1:18000`.
- Optional local DNS mode exists on the client.
- Main entrypoints:
  - `cmd/server`
  - `cmd/client`

## Source of Truth

- Read the English README first: `README.MD`
- Runtime config contracts are in:
  - `internal/config/client.go`
  - `internal/config/server.go`
- Sample configs are:
  - `client_config.toml.simple`
  - `server_config.toml.simple`
  - `client_resolvers.txt`

## What I Verified Locally

- `go test ./...` passes in this checkout.
- `go build ./cmd/client ./cmd/server` passes.
- The client/server config loaders accept TOML and JSON-base64 overrides.

## Important Runtime Facts

- Client `DOMAINS` must match server `DOMAIN`.
- `ENCRYPTION_KEY` on the client must match the server key file content.
- `DATA_ENCRYPTION_METHOD` must match on both sides.
- Client resolver list comes from `client_resolvers.txt`.
- Server key file defaults to `encrypt_key.txt`.
- Server can run direct outbound or through external SOCKS5.

## Current Project Targets

- Active logical instances (domains):
  - `1.7a8.ir`
  - `0.7x0.ir`
  - `2.a5t.ir`

## Current Client State

- Mainline mode is scanner-first (inventory owned by scanner).
- Local client config uses:
  - `DOMAINS = ["1.7a8.ir", "0.7x0.ir", "2.a5t.ir"]`
  - `LISTEN_IP = "127.0.0.1"`
  - `LISTEN_PORT = 18000`
  - `LOCAL_DNS_ENABLED = false`
  - `SCANNER_ENABLED = true`

## Client Defaults Worth Remembering

- Local SOCKS5:
  - `LISTEN_IP = "127.0.0.1"`
  - `LISTEN_PORT = 18000`
- Local DNS is off by default.
- SOCKS5 auth is off by default.

## Server Defaults Worth Remembering

- `PROTOCOL_TYPE = "SOCKS5"`
- `UDP_HOST = "0.0.0.0"`
- `UDP_PORT = 53`
- `USE_EXTERNAL_SOCKS5 = false`
- `ENCRYPTION_KEY_FILE = "encrypt_key.txt"`

## Workflow Notes

- Do not confuse local build/test success with real end-to-end product validation.
- Treat remote server validation separately from local validation.
- Keep evidence classes separate:
  - local
  - harness
  - infrastructure
  - product
- For external resource access on this workstation, the configured proxychains bundle is in `D:\proxychains_0.6.8_cygwin_x64` and it now points to `127.0.0.1:10808`.
- The Win32 proxychains bundle at `D:\proxychains_0.6.8_win32_x64` is the working one for `plink.exe` and external access on this machine.
- Run the MasterDnsVPN client directly for local app testing; do not wrap the client itself in proxychains when validating the app on this machine.
- The local client previously conflicted with the existing `127.0.0.1:10808` proxy when `LOCAL_DNS_ENABLED` was `true`; disabling the local DNS listener avoids that collision.

## Current Blocker

- No current blocker for the basic server/client deployment path.
