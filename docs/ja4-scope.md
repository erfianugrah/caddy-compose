# JA4 TLS Fingerprinting — Implementation Scope

## Architecture

```
TCP connection arrives
       │
       ▼
┌─────────────────────────┐
│ ddos_mitigator (layer4)  │  Jail check + TCP RST (existing)
└──────────┬──────────────┘
           │
           ▼
┌─────────────────────────┐
│ ja4 listener wrapper     │  NEW: Read ClientHello, compute JA4,
│ (caddy.ListenerWrapper)  │  store in registry, rewind bytes
└──────────┬──────────────┘
           │ RewindConn (bytes replayed)
           ▼
┌─────────────────────────┐
│ tls listener wrapper     │  Normal TLS handshake (existing)
└──────────┬──────────────┘
           │
           ▼
┌─────────────────────────┐
│ policy_engine            │  Read JA4 from registry, evaluate
│ (ServeHTTP)              │  rules with ja4 condition field
└─────────────────────────┘
```

Caddyfile ordering:
```caddyfile
{
    servers {
        listener_wrappers {
            layer4 { ... }
            ja4                   # ← NEW: before tls
            tls
        }
    }
}
```

## Approach Decision: Listener Wrapper (not GetConfigForClient)

**Why not GetConfigForClient:**
- Caddy manages TLS internally. HTTP handler plugins can't hook
  `tls.Config.GetConfigForClient` without modifying Caddy's TLS module.
- `GetConfigForClient` fires during the handshake — the callback can read
  `ClientHelloInfo` but there's no supported way for a third-party Caddy
  plugin to inject its own callback alongside Caddy's.

**Why listener wrapper:**
- Sits before TLS in the listener chain. Full control over raw bytes.
- Proven pattern: caddy-ja3 uses this approach (37 stars, stable).
- Our DDoS mitigator already uses a listener_wrappers block (via caddy-l4).
- No dependency on Caddy's internal TLS configuration.

**Why not use caddy-ja3 directly:**
- caddy-ja3 computes JA3 (MD5-based), not JA4.
- caddy-ja3 depends on `dreadl0ck/tlsx` for ClientHello parsing. We want
  zero external deps beyond Caddy + zap (matching the policy engine's approach).
- caddy-ja3 sets JA3 as a request header. We want it as a Caddy variable
  and policy engine condition field — tighter integration.

## New Files in caddy-policy-engine

| File | Lines | Purpose |
|------|-------|---------|
| `ja4.go` | ~300 | ClientHello binary parser + JA4 computation + GREASE filter |
| `ja4_listener.go` | ~200 | `caddy.ListenerWrapper` module: Accept → ReadClientHello → compute → store → RewindConn |
| `ja4_registry.go` | ~50 | `sync.Map` keyed by remote addr, with cleanup on conn close |
| `ja4_rewind.go` | ~40 | RewindConn: replays buffered bytes then passes through |
| `ja4_test.go` | ~250 | Unit tests for parser, JA4 computation, GREASE filtering |

**Total: ~840 lines.**

## Modifications to Existing Files

### policyengine.go

**ServeHTTP** — after RLock snapshot (line ~530), before rule loop:
```go
// Read JA4 from the listener wrapper registry.
ja4 := ja4Registry.Get(r.RemoteAddr)
if ja4 != "" {
    caddyhttp.SetVar(r.Context(), "policy_engine.ja4", ja4)
}
```

**Condition field extraction** — in `extractFieldValue()`, add:
```go
case "ja4":
    return ja4Registry.Get(r.RemoteAddr)
```

**validConditionFields** — add `"ja4": true`.

### wafctl (caddy-compose)

**models_exclusions.go** — `validConditionFields`: add `"ja4": true`.

**waf-dashboard** — `constants.ts` `CONDITION_FIELDS`: add ja4 field with
operators `eq`, `neq`, `in`, `not_in`, `in_list`, `not_in_list`, `regex`.

## JA4 Computation Algorithm (from FoxIO spec)

### Format: `{a}_{b}_{c}`

**Section a (10 chars):**
```
{protocol}{version}{sni}{cipher_count}{ext_count}{alpn}
```
- protocol: `t` (TCP/TLS)
- version: highest non-GREASE from supported_versions, or protocol version
- sni: `d` if ServerName present, `i` if not
- cipher_count: 2-digit zero-padded count (after GREASE removal)
- ext_count: 2-digit zero-padded count (after GREASE removal)
- alpn: first + last alphanumeric char of first ALPN value, or `00`

**Section b (12 chars):**
- Sort cipher suite hex values (4-char lowercase), excluding GREASE
- Join with commas
- SHA-256 → first 12 hex chars

**Section c (12 chars):**
- Sort extension hex values (4-char lowercase), excluding GREASE + SNI (0000) + ALPN (0010)
- Join with commas
- Append `_` + signature algorithms in original order (NOT sorted), comma-delimited
- SHA-256 → first 12 hex chars

### GREASE Values (filter everywhere)
```
0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a,
0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba,
0xcaca, 0xdada, 0xeaea, 0xfafa
```

## ClientHello Binary Parser (hand-rolled, no deps)

The TLS ClientHello is a binary protocol (RFC 8446 §4.1.2):

```
TLS Record Layer (5 bytes):
  content_type:    1 byte  (0x16 = Handshake)
  protocol_version: 2 bytes (0x0301 for TLS 1.0 compat)
  length:          2 bytes  (big-endian)

Handshake Header (4 bytes):
  msg_type:        1 byte  (0x01 = ClientHello)
  length:          3 bytes  (big-endian, 24-bit)

ClientHello body:
  client_version:  2 bytes
  random:          32 bytes
  session_id:      1 byte length + variable
  cipher_suites:   2 bytes length + variable (each suite = 2 bytes)
  compression:     1 byte length + variable
  extensions:      2 bytes length + variable
    each extension:
      type:        2 bytes
      length:      2 bytes
      data:        variable
        (for ALPN 0x0010: 2-byte list length, then strings with 1-byte length prefix)
        (for sig_algs 0x000d: 2-byte list length, then 2-byte scheme values)
        (for supported_versions 0x002b: 1-byte list length, then 2-byte version values)
```

The parser needs to extract:
1. Cipher suite list (uint16[])
2. Extension type list (uint16[])
3. ALPN protocol list (string[]) — from extension 0x0010
4. Signature algorithm list (uint16[]) — from extension 0x000d
5. Supported versions list (uint16[]) — from extension 0x002b

This is straightforward binary parsing — no ASN.1, no certificate handling.
Total: ~150 lines of `encoding/binary` code.

## Listener Wrapper Module

```go
// Module ID: caddy.listeners.ja4
type JA4ListenerWrapper struct {
    logger *zap.Logger
}

func (JA4ListenerWrapper) CaddyModule() caddy.ModuleInfo {
    return caddy.ModuleInfo{
        ID:  "caddy.listeners.ja4",
        New: func() caddy.Module { return new(JA4ListenerWrapper) },
    }
}

func (w *JA4ListenerWrapper) WrapListener(ln net.Listener) net.Listener {
    return &ja4Listener{Listener: ln, logger: w.logger}
}

type ja4Listener struct {
    net.Listener
    logger *zap.Logger
}

func (l *ja4Listener) Accept() (net.Conn, error) {
    conn, err := l.Listener.Accept()
    if err != nil { return conn, err }

    // Read ClientHello bytes (TLS record: 5-byte header + payload)
    raw, err := readClientHello(conn)
    if err != nil {
        // Not TLS or malformed — pass through unchanged
        return newRewindConn(conn, raw), nil
    }

    // Parse ClientHello and compute JA4
    ch, err := parseClientHello(raw)
    if err == nil {
        ja4 := computeJA4(ch)
        ja4Registry.Set(conn.RemoteAddr().String(), ja4)
    }

    // Rewind bytes and wrap conn to clean up registry on close
    return newJA4Conn(newRewindConn(conn, raw), conn.RemoteAddr().String()), nil
}
```

The `ja4Conn` wrapper calls `ja4Registry.Delete(addr)` on `Close()`.

## RewindConn

```go
type rewindConn struct {
    net.Conn
    buf    *bytes.Reader
    closed bool
}

func (c *rewindConn) Read(p []byte) (int, error) {
    if c.buf.Len() > 0 {
        n, err := c.buf.Read(p)
        if err == io.EOF {
            return n, nil // seamless transition to real conn
        }
        return n, err
    }
    return c.Conn.Read(p)
}
```

## JA4 Registry

```go
var ja4Registry ja4Store

type ja4Store struct {
    m sync.Map // key: "ip:port" string, value: string (JA4 fingerprint)
}

func (s *ja4Store) Set(addr, ja4 string) { s.m.Store(addr, ja4) }
func (s *ja4Store) Get(addr string) string {
    v, ok := s.m.Load(addr)
    if !ok { return "" }
    return v.(string)
}
func (s *ja4Store) Delete(addr string) { s.m.Delete(addr) }
```

Cleanup: `ja4Conn.Close()` deletes the entry. No TTL needed — entries are
removed when the TCP connection closes.

## Caddyfile Integration

Current production Caddyfile:
```caddyfile
servers {
    listener_wrappers {
        layer4 {
            route {
                ddos_mitigator { jail_file /data/waf/jail.json }
            }
        }
        tls
    }
}
```

After adding JA4:
```caddyfile
servers {
    listener_wrappers {
        layer4 {
            route {
                ddos_mitigator { jail_file /data/waf/jail.json }
            }
        }
        ja4              # ← NEW: between L4 and TLS
        tls
    }
}
```

The `ja4` wrapper must be AFTER `layer4` (so jailed IPs are dropped before
wasting cycles on ClientHello parsing) and BEFORE `tls` (so it can read the
raw ClientHello before Go's TLS stack consumes it).

## Testing Strategy

**Unit tests (ja4_test.go):**
- Parse known ClientHello byte sequences → verify extracted fields
- Compute JA4 for Chrome/Firefox/curl → verify against published fingerprints
- GREASE filtering correctness
- Edge cases: no ALPN, no sig algs, empty extensions, malformed records

**E2E tests:**
- Can't test in the e2e Docker stack (plain HTTP, no TLS)
- Test live on production (httpbun.erfi.io, which terminates TLS at Caddy)
- Create a rule matching `ja4` condition field, deploy, verify

**Playwright tests:**
- Playwright's headless Chromium has a known JA4 — verify it's captured

## Session Tickets / Resumption

When a client resumes a TLS session (via session tickets or PSK), it sends an
abbreviated ClientHello. The cipher suites and extensions may differ from the
full handshake. caddy-ja3 forcibly disables session tickets to always get a
full ClientHello.

**Our approach:** Do NOT disable session tickets (that would degrade TLS
performance). Instead, if a ClientHello appears truncated (missing expected
fields), set JA4 to the empty string. The policy engine treats empty JA4 as
"no fingerprint available" — rules using `ja4` conditions won't match, and
the request passes through to other evaluation passes.

## Work Breakdown

| # | Task | Est. |
|---|------|------|
| 1 | `ja4.go`: ClientHello parser + JA4 computation | 1 day |
| 2 | `ja4_listener.go` + `ja4_registry.go` + `ja4_rewind.go`: Listener wrapper | 0.5 day |
| 3 | `policyengine.go`: Integrate JA4 into condition matching + Caddy vars | 0.5 day |
| 4 | `ja4_test.go`: Unit tests with known ClientHello fixtures | 0.5 day |
| 5 | wafctl: Add `ja4` to valid condition fields + dashboard | 0.5 day |
| 6 | Caddyfile update + production deployment + live testing | 0.5 day |

**Total: ~3.5 days.**
