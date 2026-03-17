# SwitchboardProxy

Lightweight proxy for inspecting, routing and manipulating network traffic in real time.

## Features

- Intercept client ⇄ server traffic
- Live routing between multiple backends
- Telnet control interface
- Packet inspection and debugging
- Works standalone (no DSL required)

## Configuration

Uses its own config file:

    config.yaml

No external dependencies required.

## Run

    python proxyserver.py

## Use cases

- Debug protocol traffic
- Replay or inspect packets
- Route between test server and external server (e.g. SkyFire)
- Experiment with packet manipulation

## Philosophy

SwitchboardProxy is a control layer.

It does not implement protocol logic — it observes and redirects traffic.
