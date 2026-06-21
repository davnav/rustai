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

## Testing

### Basic Valid Packet (IPv4 with TCP)

```bash
curl -X POST http://127.0.0.1:3000/analyze \
  -H "Content-Type: application/json" \
  -d '{"packet_hex":"4500003c1c4640004006b1e6c0a80001c0a800c7"}'
```

Expected: Returns IPv4 packet details with TCP information.

### Test 1: Invalid Hex Characters

```bash
curl -X POST http://127.0.0.1:3000/analyze \
  -H "Content-Type: application/json" \
  -d '{"packet_hex":"45000028000100004006XYZ!!0a80001c0a800c7"}'
```

Expected: `400 Bad Request` with error message about invalid hex characters.

### Test 2: Odd Length String

```bash
curl -X POST http://127.0.0.1:3000/analyze \
  -H "Content-Type: application/json" \
  -d '{"packet_hex":"450000280001000040060000c0a80001c0a800c"}'
```

Expected: `400 Bad Request` with error about even number of hex digits.

### Test 3: Truncated Data

```bash
curl -X POST http://127.0.0.1:3000/analyze \
  -H "Content-Type: application/json" \
  -d '{"packet_hex":"4500002800010000"}'
```

Expected: `200 OK` with response indicating packet too short for IPv4 header.

### Test 4: Empty Packet

```bash
curl -X POST http://127.0.0.1:3000/analyze \
  -H "Content-Type: application/json" \
  -d '{"packet_hex":""}'
```

Expected: `200 OK` with response indicating packet is empty.

### Test 5: Whitespace in Hex String

```bash
curl -X POST http://127.0.0.1:3000/analyze \
  -H "Content-Type: application/json" \
  -d '{"packet_hex":"45 00 00 3c 1c 46 40 00 40 06 b1 e6 c0 a8 00 01 c0 a8 00 c7"}'
```

Expected: `200 OK` - whitespace is ignored, packet is parsed normally.

### Test 6: IPv6 Packet

```bash
curl -X POST http://127.0.0.1:3000/analyze \
  -H "Content-Type: application/json" \
  -d '{"packet_hex":"60000000002a1140fe8000000000000000000000000000012000000000000000000000000000001"}'
```

Expected: `200 OK` with IPv6 packet details.

### Test 7: Minimal IPv4 Header (20 bytes)

```bash
curl -X POST http://127.0.0.1:3000/analyze \
  -H "Content-Type: application/json" \
  -d '{"packet_hex":"4500001400001000401100000a0000010a000002"}'
```

Expected: `200 OK` with IPv4 packet analysis (UDP header follows).

### Test 8: Packet with ICMP

```bash
curl -X POST http://127.0.0.1:3000/analyze \
  -H "Content-Type: application/json" \
  -d '{"packet_hex":"450000541234000040010000c0a80001c0a80002080056d4000100"}'
```

Expected: `200 OK` with IPv4 packet details showing ICMP protocol.

### Test 9: Unknown IP Version

```bash
curl -X POST http://127.0.0.1:3000/analyze \
  -H "Content-Type: application/json" \
  -d '{"packet_hex":"F5000000000000000000000000000000"}'
```

Expected: `200 OK` with response indicating unsupported IP version.

### Test 10: Single Byte (Too Short)

```bash
curl -X POST http://127.0.0.1:3000/analyze \
  -H "Content-Type: application/json" \
  -d '{"packet_hex":"45"}'
```

Expected: `200 OK` but packet too short to fully parse.

## Notes

- `packet_hex` may contain whitespace for readability.
- The service parses IPv4 and IPv6 packets and reports basic TCP/UDP/ICMP transport information.
- Invalid hex characters result in a `400 Bad Request` response.
- Malformed packets (too short, unknown versions) return `200 OK` with descriptive error details in the response JSON.
