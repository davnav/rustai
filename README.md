# rustai

AI tools built on Rust.

## Project overview

This repository includes `aicrab`, a small Rust HTTP service that analyzes packet data sent as hexadecimal strings.

## Prerequisites

- Rust toolchain installed (recommended via `rustup`)
- `cargo` available on your `PATH`

## Install and setup

1. Open a terminal in the repository root.
2. Change into the `aicrab` directory:
   ```bash
   cd aicrab
   ```
3. Build the project:
   ```bash
   cargo build
   ```

## Run the service

Start the packet analysis server:

```bash
cargo run
```

The service listens on `http://127.0.0.1:3000`.

## How to use

### Root endpoint

Send a `GET` request to confirm the service is running:

```bash
curl http://127.0.0.1:3000/
```

### Analyze a packet

Send a `POST` request to `/analyze` with JSON containing a `packet_hex` field.

Example:

```bash
curl -X POST http://127.0.0.1:3000/analyze \
  -H "Content-Type: application/json" \
  -d '{"packet_hex":"4500003c1c4640004006b1e6c0a80001c0a800c7"}'
```

The server returns JSON with packet metadata, including format, packet length, source/destination addresses, protocol, and transport-layer details.

## Notes

- `packet_hex` may contain whitespace for readability.
- The service parses IPv4 and IPv6 packets and reports basic TCP/UDP/ICMP transport information.
