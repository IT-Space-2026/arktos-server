# Arktos Rendezvous Server

A minimal, stateless relay that lets two Arktos devices find each other
and pair **without either device hosting an onion service** — both sides
make outbound Tor connections only.

## Why it exists

Arktos pairing is a Noise-XX handshake over a bidirectional stream.
Today that stream is either:

- **LAN QUIC** — great on the same network, impossible across networks.
- **Tor onion service** — the inviter *publishes* an onion service and
  the joiner dials it. Publishing requires the inviter's Tor daemon to
  maintain introduction points on a real home network, which is the
  single least reliable step in the whole pipeline (`DegradedUnreachable`).

The rendezvous server removes the second failure surface: **only the
server hosts an onion service**. A VPS datacenter keeps intro points
far more reliably than a residential NAT ever will.

## How it works

```
inviter (desktop)                       joiner (mobile)
        │                                      │
        ▼                                      ▼
   dial relay onion ──► "OFFER <H(token)>"     │
        │ holds stream open                    │
        │                    "CLAIM <H(token)>" ◄── dial relay onion
        │                                      │
        ▼                                      ▼
   server matches H(token), splices the two streams byte-for-byte
        │                                      │
        ▼              Noise-XX (ciphertext)   ▼
   inviter ◄──────────────────────────────────► joiner
        fingerprint confirm → paired → relay drops out
```

After pairing, sync runs **device-to-device** (LAN or tor between the
devices themselves). The relay is only a matchmaker — it never carries
sync traffic.

## Wire protocol

One header line per inbound stream, then opaque bytes:

```
OFFER <64-hex>      park this stream under H(token), await a peer
CLAIM <64-hex>      look up H(token); splice to the parked stream
                    or close with an error
```

- `H(token)` is SHA-256 of the pairing token — the raw pairing code
  **never reaches the server**.
- After a CLAIM match the server copies bytes in both directions and
  does nothing else. Everything that follows is encrypted Noise
  handshake frames the server cannot read.
- Max 8 pending offer streams per identity address at a time;
  offers expire after `OFFER_TTL` (default 5 min).

## What the server can and cannot see

| Sees | Cannot see |
|---|---|
| an opaque 32-byte hash per pairing | the pairing code/token |
| two TCP/Tor stream handles for seconds | frame contents (Noise ciphertext) |
| that *a* pairing happened, and when | which devices, their keys, or IPs |

Persistent state: **none**. The pending-offer table is in-memory only,
entries live seconds, nothing touches disk, nothing survives restart.

## Components

One binary, two modes:

```
arktos-server            supervisor + admin UI (spawns & manages "serve")
arktos-server serve      the actual relay (onion service + splice)
```

### Admin page

`http://127.0.0.1:8080` — shows relay status (running/stopped, pid,
uptime, onion address) with **Start / Stop / Restart** buttons and a
live log tail. Bound to localhost only — expose through SSH tunnel:

```
ssh -L 8080:127.0.0.1:8080 user@your-vps
```

## Deploy

```bash
cargo build --release
./target/release/arktos-server          # supervisor + admin on :8080
# prints the relay's onion address once published — put it in the apps
```

Server sizing: 1 vCPU / 512 MB RAM / a $3-5 VPS is plenty. Traffic is a
few KB per pairing; thousands of pairings/day ≈ a few GB/month.

## Security notes

- Frames are end-to-end Noise-encrypted — the relay is a dumb pipe.
- Only the token *hash* is stored, and only transiently — a log-less
  build (`ARKTOS_LOG=off`) cannot retain pairing data at all.
- The relay learns timing metadata ("a pairing happened at T") — run it
  yourself for maximum control, or treat it like a STUN server: needed
  to find peers, never trusted with content.
- DoS surface is bounded: offers are capped per source and expire.
