---
name: deploy-ech-tunnel
description: Deploy ech-tls-tunnel + ssserver on a Linux VPS (port 443, ACME auto-renew, optional unowned cover name) and the matching sslocal client as a macOS LaunchAgent HTTP/HTTPS proxy. Use when the user asks to set up, redeploy, rotate keys, or change the cover name for the SIP003 tunnel.
---

# deploy-ech-tunnel

End-to-end playbook for a working **ech-tls-tunnel** deployment:

```
┌─ macOS client ──────────────┐         ┌─ Linux VPS (port 443) ──────┐
│ sslocal --plugin ett        │  TLS+   │ ssserver --plugin ett       │
│   --protocol http           │  ECH+WS │   (acme auto-issue/renew)   │
│   -b 127.0.0.1:8080         │ ───────►│   :443 → 127.0.0.1:<random> │
└─────────────────────────────┘         └─────────────────────────────┘
```

The plugin is a SIP003 child process of `ssserver`/`sslocal`. Everything
lives in `SS_PLUGIN_OPTIONS` — no separate config file.

## Inputs you need before starting

| Variable | Example | Notes |
|---|---|---|
| `SERVER_HOST` | `vps.example.com` | A-record points at the VPS, port 443 free |
| `TUNNEL_DOMAIN` | `vps.example.com` | Cert SAN; inner SNI. Usually = `SERVER_HOST` |
| `COVER_NAME` | `www.cloudflare.com` | Outer SNI seen on the wire. Can be unowned (see "Cover-name strategy") |
| `SS_PASSWORD` | `<32+ random chars>` | Shared secret. `openssl rand -base64 24` works |
| `SS_METHOD` | `aes-128-gcm` | Any cipher both ends understand |
| `WS_PATH` | `/ws-<16 hex>` | Secret WebSocket path. `/ws-$(openssl rand -hex 8)` |
| `ACME_EMAIL` | `you@example.com` | Let's Encrypt contact |

## 1. Server side (Linux VPS, root)

### 1.1 Install binaries

```sh
# pick the right asset for your arch — linux-amd64 or linux-arm64
curl -L https://github.com/shadowsocks/ech-tls-tunnel/releases/latest/download/ech-tls-tunnel-linux-amd64.tar.gz \
  | tar xz -C /usr/local/bin/
chmod +x /usr/local/bin/ech-tls-tunnel

# ssserver from shadowsocks-rust
SS_VER=v1.24.0
curl -L https://github.com/shadowsocks/shadowsocks-rust/releases/download/$SS_VER/shadowsocks-$SS_VER.x86_64-unknown-linux-gnu.tar.xz \
  | tar xJ -C /usr/local/bin/ ssserver
chmod +x /usr/local/bin/ssserver
```

If you control the source and need an updated binary built from a fresh
commit, use the repo's `release.yml` workflow instead of building on the
VPS — small VPSes (≤512 MB RAM) OOM compiling BoringSSL:

```sh
gh workflow run release.yml --ref main
# wait
gh run download <run-id> -n ech-tls-tunnel-linux-amd64 -D /tmp/ett
tar xz -f /tmp/ett/ech-tls-tunnel-linux-amd64.tar.gz -C /tmp/ett
cp -v /usr/local/bin/ech-tls-tunnel /usr/local/bin/ech-tls-tunnel.bak  # always back up
scp /tmp/ett/ech-tls-tunnel root@$SERVER_HOST:/usr/local/bin/ech-tls-tunnel.new
ssh root@$SERVER_HOST 'chmod +x /usr/local/bin/ech-tls-tunnel.new && \
  mv /usr/local/bin/ech-tls-tunnel.new /usr/local/bin/ech-tls-tunnel && \
  systemctl restart ssserver-ech'
```

### 1.2 Generate ECH HPKE keypair

The `public_name` is **baked into** the ECHConfigList, so each cover
name has its own keypair. Keep the directory name self-documenting:

```sh
mkdir -p /var/lib/ech-tls-tunnel/ech-${COVER_TAG}
ech-tls-tunnel ech-gen-keys \
    --public-name ${COVER_NAME} \
    --out /var/lib/ech-tls-tunnel/ech-${COVER_TAG}
```

The command prints the base64 `ECHConfigList` — **save it**, every
client needs that exact string in `ech_config=`.

### 1.3 systemd unit

```sh
cat >/etc/systemd/system/ssserver-ech.service <<EOF
[Unit]
Description=Shadowsocks server with ech-tls-tunnel plugin
After=network.target

[Service]
ExecStart=/usr/local/bin/ssserver \\
    -s 0.0.0.0:443 \\
    -k ${SS_PASSWORD} \\
    -m ${SS_METHOD} \\
    --plugin /usr/local/bin/ech-tls-tunnel \\
    --plugin-opts "mode=server;domain=${TUNNEL_DOMAIN};path=${WS_PATH};acme_email=${ACME_EMAIL};acme_cache=/var/lib/ech-tls-tunnel/acme;ech_public_name=${COVER_NAME};ech_key=/var/lib/ech-tls-tunnel/ech-${COVER_TAG}/ech.key;acme_cover_san=false"
Restart=on-failure
RestartSec=5
LimitNOFILE=65536
AmbientCapabilities=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now ssserver-ech
journalctl -u ssserver-ech -f   # watch first ACME order
```

Server-only plugin options summary:

| Key | Default | When to set |
|---|---|---|
| `domain` | (required) | Real tunnel domain — cert SAN, inner SNI |
| `path` | (required) | `/ws-<16hex>` — non-matching requests get fake nginx 404 |
| `acme_email` | — | Enables Let's Encrypt issuance + auto-renewal (TLS-ALPN-01) |
| `acme_cache` | `/var/lib/ech-tls-tunnel/acme` | Cert + account state across restarts |
| `acme_staging` | `false` | Set `true` only while testing — strict prod rate limits otherwise |
| `acme_cover_san` | `true` | **Set `false` if `ech_public_name` is a domain you don't own** — otherwise ACME order fails |
| `ech_public_name` | — | Outer SNI. With `ech_key`, enables ECH |
| `ech_key` | — | Path to HPKE private key from `ech-gen-keys` |
| `reject_non_ech` | `true` | TCP-RST inbound handshakes that lack ECH (and aren't ACME validators). Defends cover from active probes. Only effective when ECH is enabled |
| `server_name` | `nginx/1.24.0` | `Server` header on the fake-404 |

### 1.4 Verify

```sh
systemctl is-active ssserver-ech                # active
ss -tlnp | grep :443                            # ech-tls-tunnel listening
journalctl -u ssserver-ech -n 30                # ECH enabled, cert issued/cached
```

## 2. macOS client (per machine)

### 2.1 Install binaries

```sh
# sslocal — either via cargo or homebrew (shadowsocks-rust)
cargo install shadowsocks-rust --bin sslocal --features local-http
# or:
brew install shadowsocks-rust

# ech-tls-tunnel — darwin-arm64 (M-series Macs)
mkdir -p ~/.local/bin
curl -L https://github.com/shadowsocks/ech-tls-tunnel/releases/latest/download/ech-tls-tunnel-darwin-arm64.tar.gz \
  | tar xz -C ~/.local/bin/
chmod +x ~/.local/bin/ech-tls-tunnel
mkdir -p ~/Library/Logs/ech-tls-tunnel
```

### 2.2 LaunchAgent plist

`~/Library/LaunchAgents/com.<you>.ech-tls-tunnel.plist` — chmod 600
because it contains `SS_PASSWORD`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.YOU.ech-tls-tunnel</string>
    <key>ProgramArguments</key>
    <array>
        <string>/Users/YOU/.cargo/bin/sslocal</string>
        <string>-b</string><string>127.0.0.1:8080</string>
        <string>-s</string><string>SERVER_HOST:443</string>
        <string>-k</string><string>SS_PASSWORD</string>
        <string>-m</string><string>SS_METHOD</string>
        <string>--protocol</string><string>http</string>
        <string>--plugin</string><string>/Users/YOU/.local/bin/ech-tls-tunnel</string>
        <string>--plugin-opts</string>
        <string>mode=client;sni=TUNNEL_DOMAIN;path=WS_PATH;ech_config=ECH_CONFIGLIST_BASE64</string>
    </array>
    <key>RunAtLoad</key><true/>
    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key><false/>
        <key>NetworkState</key><true/>
    </dict>
    <key>ThrottleInterval</key><integer>5</integer>
    <key>ProcessType</key><string>Background</string>
    <key>StandardOutPath</key><string>/Users/YOU/Library/Logs/ech-tls-tunnel/sslocal.out.log</string>
    <key>StandardErrorPath</key><string>/Users/YOU/Library/Logs/ech-tls-tunnel/sslocal.err.log</string>
</dict>
</plist>
```

`--protocol http` accepts both ordinary HTTP and HTTPS-via-CONNECT on
the same port, so a single 8080 endpoint covers everything. Use
`--protocol socks` instead if you need SOCKS5.

Client-only options summary:

| Key | Default | When to set |
|---|---|---|
| `sni` | (required) | Inner SNI = `TUNNEL_DOMAIN`. Cert is validated against this |
| `ech_config` | — | Base64 ECHConfigList from server's `ech-gen-keys` |
| `ech_config_file` | — | Alternative: path to binary ECHConfigList |
| `ca_file` | — | Pin a CA bundle. Mutually exclusive with `insecure` |
| `insecure` | `false` | DEV/TEST ONLY |
| `fingerprint` | — | `chrome\|firefox\|safari\|ios\|android\|edge\|random` for ClientHello shaping |

### 2.3 Load & verify

```sh
chmod 600 ~/Library/LaunchAgents/com.YOU.ech-tls-tunnel.plist
plutil -lint ~/Library/LaunchAgents/com.YOU.ech-tls-tunnel.plist
launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/com.YOU.ech-tls-tunnel.plist

# state should be running, last-exit-code never:
launchctl print gui/$(id -u)/com.YOU.ech-tls-tunnel | grep -E 'state|pid|last exit'

# functional test — exit IP must equal SERVER_HOST's public IP:
curl -x http://127.0.0.1:8080 https://ifconfig.me
```

System-wide: **System Settings → Network → (interface) → Details →
Proxies**, enable *Web Proxy (HTTP)* + *Secure Web Proxy (HTTPS)* with
`127.0.0.1:8080`. Or `export http_proxy=http://127.0.0.1:8080
https_proxy=http://127.0.0.1:8080` in your shell rc.

## 3. Cover-name strategy

`ech_public_name` is what passive observers see in the outer SNI. ECH
encrypts the inner ClientHello (with the real `domain`) regardless,
so cryptographically anything works in the cleartext field. The
ownership question is about *active probing*:

| Cover | Passive observers | Active probe | Setup |
|---|---|---|---|
| Same as `domain` | See real domain | Cert matches | No extra work, **but ECH gives you nothing** |
| Owned subdomain (`cdn.yourdomain.com`) pointing at the VPS | See benign hostname | Cert is valid for cover too | DNS A-record + `acme_cover_san=true` (default) |
| Random (`www.cloudflare.com`) | See plausible big-name target | Cert mismatch — only `domain` covered | `acme_cover_san=false`; `reject_non_ech=true` (default) hides the mismatch behind a TCP-RST |

For "passive ISP / SNI logger" threat models, the random-cover variant
with `reject_non_ech=true` is the practical choice. For active GFW-class
adversaries you need the owned cover.

## 4. Rotating the cover name

1. On the server, generate fresh keys with the new public_name into a
   *new* directory (don't overwrite — keeps rollback trivial):

   ```sh
   mkdir -p /var/lib/ech-tls-tunnel/ech-${NEW_TAG}
   ech-tls-tunnel ech-gen-keys --public-name ${NEW_COVER} --out /var/lib/ech-tls-tunnel/ech-${NEW_TAG}
   ```

2. Edit `/etc/systemd/system/ssserver-ech.service` — update
   `ech_public_name`, `ech_key=…/ech-${NEW_TAG}/ech.key`, and toggle
   `acme_cover_san` if ownership changed.
3. `systemctl daemon-reload && systemctl restart ssserver-ech`.
4. Distribute the **new** `ECHConfigList` base64 to every client and
   update each `ech_config=` plugin option. Clients with the old
   ECHConfig will fail until updated.
5. After all clients have rolled over, you can delete the old
   `/var/lib/ech-tls-tunnel/ech-<old-tag>/` directory and the unit
   `.bak`.

## 5. Troubleshooting

| Symptom | Likely cause |
|---|---|
| Server logs `issuing new cert via ACME` then errors with `urn:ietf:params:acme:error:rateLimited` | You used the wrong cover name and ACME tried to issue for `ech_public_name`. Set `acme_cover_san=false` and remove the `acme_email`-cached failed order |
| Client errors `tls handshake: ssl: ECH rejected` | ECHConfigList drift — server keys rotated but client still has old `ech_config=`. Update client |
| `connection refused` on 127.0.0.1:8080 | `launchctl print gui/$UID/<label>` and check `last exit code`; tail `sslocal.err.log` |
| Server active but `curl` via proxy times out | Outer SNI policy — confirm `reject_non_ech` isn't blocking a *legitimate* non-ECH path (e.g. a misconfigured client). Temporarily set `reject_non_ech=false` to test |
| `ech-tls-tunnel` exits with `BoringSSL ECH key load failed` | `ech_key` path doesn't match the public_name baked into the corresponding `ech.config_list` — regenerate the pair as a unit |

## 6. Useful commands

```sh
# server
systemctl restart ssserver-ech
journalctl -u ssserver-ech -f
ss -tlnp | grep :443
openssl s_client -connect SERVER_HOST:443 -servername COVER_NAME </dev/null 2>&1 | head

# macOS client
launchctl bootout   gui/$(id -u)/com.YOU.ech-tls-tunnel
launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/com.YOU.ech-tls-tunnel.plist
launchctl kickstart -k gui/$(id -u)/com.YOU.ech-tls-tunnel
tail -f ~/Library/Logs/ech-tls-tunnel/sslocal.err.log
curl -x http://127.0.0.1:8080 https://ifconfig.me
```
