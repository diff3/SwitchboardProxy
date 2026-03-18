# Proxy

Read-only TCP proxy for observing auth and world traffic.

## What It Does

- listens on one or more local routes
- forwards traffic unchanged
- parses WoW packets from the TCP stream
- resolves opcode names
- can decode payloads through the shared DSL runtime
- supports live control through the telnet CLI

The proxy is intentionally read-only. It may inspect, log, decode, dump and filter output, but it must not modify forwarded packet bytes.

## Configuration

Proxy configuration lives in:

`/home/magnus/projects/PyPandariaEmu/config/proxy.json`

It stays JSON even though the other services use YAML.

Important top-level fields:

- `shared.buffer_size`
- `shared.write_to_log`
- `shared.log_file`
- `shared.listen_host`
- `shared.proxy.adapters`
- `shared.proxy.logging`
- `shared.proxy.filter`
- `shared.proxy.capture`
- `states.default.routes`
- `states.<name>.routes`

## Logging

The proxy now uses the shared `Logger` just like authserver and worldserver.

- log file is controlled by `shared.log_file`
- file logging is controlled by `shared.write_to_log`
- the proxy log is reset on startup, so it only contains the current session

## Packet Parsing

The proxy follows the same packet parsing rules as the servers:

- auth packets are parsed with auth framing
- world plaintext packets use the same plain parser as worldserver
- encrypted world packets are parsed after world crypto is initialized from `CMSG_AUTH_SESSION`
- opcode decode uses the shared opcode maps
- payload decode uses the shared `DslRuntime`

If a `.def` file exists, the proxy can decode the payload. If not, it can still show opcode + raw payload.

## CLI / Telnet

The telnet CLI supports:

- live logging changes
- per-scope settings: global, `auth`, `world`, or `route <name>`
- blacklist / whitelist
- capture dump and focus dump
- promote / demote / protocol commands
- tab completion for commands, route names and opcode names

## Run

From project root:

```bash
python proxyserver.py
```

## Notes

- routes are configured by name, not by index
- multiple world routes on different ports are supported
- the proxy can decode full packet payloads, but forwarding stays unchanged
