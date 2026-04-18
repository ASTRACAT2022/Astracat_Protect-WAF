# ASTRACAT PROTECT

Reverse-proxy / edge-gateway with Auto-HTTPS, L7, WAF ,protections, and metrics.

## Быстрый старт

```bash
./install
```

## Документация

- `INSTALL.md` — локальная сборка и запуск
- `DOCKER_DEPLOY.md` — production deploy в Docker, конфиги и диагностика
- `DOCKER_AI_MANUAL_RU.md` — Docker сборка/запуск с ONNX/TFLite hooks, HTTP/3, DNS-01
- `NEW_FEATURES_MANUAL_RU.md` — отдельный мануал по новым функциям

## Запуск (dev)

```bash
ADMIN_TOKEN=changeme \
./bin/astracat-protect \
  -config configs/astra.yaml \
  -http :80 \
  -https :443 \
  -admin :9090
```

## Endpoints

- Public: `/healthz`, `/metrics`
- Admin: `/healthz`, `/metrics`, `/reload` (Bearer token)

## Env overrides

ACME:
- `ACME_EMAIL`
- `ACME_CA`
- `ACME_STAGING` (true/1)
- `ACME_KEY_TYPE`
- `ACME_RENEW_WINDOW`
- `ACME_STORAGE` (default `/data/acme`)
- `ON_DEMAND_TLS` (true/1, issues cert on first TLS handshake)
- `ACME_DNS01` (true/1, enables DNS-01 certificate flow via hooks)
- `ACME_DNS_ISSUE_HOOK` (command template with `{domain} {storage} {cert} {key}`)
- `ACME_DNS_RENEW_HOOK` (optional, same placeholders; fallback = issue hook)
- `ACME_DNS_HOOK_TIMEOUT` (seconds)
- `ACME_DNS_STORAGE` (default `/data/acme/dns01`)
- `SSL_MODE` (`internal` or `custom`)
- `SSL_CERT_FILE`, `SSL_KEY_FILE` (global custom cert pair)
- `SSL_CERT_DIR` (per-domain cert lookup: `<domain>.crt` + `<domain>.key` or `<domain>/fullchain.pem` + `<domain>/privkey.pem`)

Admin:
- `ADMIN_TOKEN` (required for /reload)

Limits:
- `RATE_LIMIT_RPS`
- `RATE_LIMIT_BURST`
- `CONN_LIMIT`
- `WS_CONN_LIMIT`
- `WHITELIST_IPS` (comma-separated IP/CIDR, e.g. `95.27.149.224,172.18.0.0/16`)
- `MAX_BODY_BYTES`
- `MAX_URI_BYTES`
- `MAX_QUERY_BYTES`
- `MAX_PARAMS`
- `MAX_HEADER_BYTES`
- `MAX_URL_LENGTH`
- `RISK_THRESHOLD`
- `RISK_TTL` (seconds)
- `RISK_STATUS_WINDOW` (seconds)
- `BAN_AFTER` (violations before ban, default `3`)
- `BAN_SECONDS` (ban duration, default `3600`)
- `RATE_429_BAN_AFTER`
- `RATE_429_WINDOW_SECONDS`
- `RATE_429_BAN_SECONDS`
- `WAF_BAN_SECONDS`
- `limits.rate_policies` in YAML for route-specific token buckets (e.g. `/api/*`, `/login`)

Challenge:
- `CHALLENGE_TTL` (seconds)
- `CHALLENGE_BIND_IP` (true/1)
- `CHALLENGE_BIND_UA` (true/1)

WAF:
- `WAF_ENABLED` (true/1)
- `WAF_MODE` (`block` or `log`)
- `WAF_LEVEL` (`low|medium|high|ultra|off`, quick profile for paranoia + thresholds)
- `WAF_SCORE_THRESHOLD`
- `WAF_INBOUND_THRESHOLD`
- `WAF_PARANOIA_LEVEL` (1..4)
- `WAF_MAX_INSPECT_BYTES`
- `WAF_MAX_VALUES_PER_COLLECTION`
- `WAF_MAX_TOTAL_VALUES`
- `WAF_MAX_JSON_VALUES`
- `WAF_MAX_BODY_VALUES`
- `WAF_ALLOWED_METHODS` (comma-separated, e.g. `GET,POST,PUT,PATCH,DELETE,OPTIONS,HEAD`)
- `WAF_BLOCKED_CONTENT_TYPES` (comma-separated regex fragments)
- `waf.exempt_globs`, `waf.exempt_hosts`, `waf.exempt_rule_ids`, `waf.exempt_rule_ids_by_glob` in YAML for precise production exceptions

Auto Shield (fully automatic adaptive protection):
- `AUTO_SHIELD_ENABLED` (true/1)
- `AUTO_SHIELD_WINDOW_SECONDS`
- `AUTO_SHIELD_MIN_REQUESTS`
- `AUTO_SHIELD_PROBE_PATH_THRESHOLD`
- `AUTO_SHIELD_HIGH_ERROR_RATIO_PCT`
- `AUTO_SHIELD_HIGH_RATE_LIMIT_RATIO_PCT`
- `AUTO_SHIELD_SCORE_THRESHOLD`
- `AUTO_SHIELD_BAN_SECONDS`
- `servers[].auto_shield_enabled` in YAML overrides global mode for specific host

HTTP/3:
- `HTTP3_ENABLED` (true/1)
- `HTTP3_LISTEN` (default `:443`)

AI-WAF adaptive engine:
- `AI_ENABLED` (true/1)
- `AI_LEARNING_MODE` (true/1)
- `AI_BACKEND` (`builtin` | `onnx` | `tflite`)
- `AI_MODEL_PATH`
- `AI_ONNX_COMMAND`, `AI_TFLITE_COMMAND` (stdin JSON -> stdout JSON `{score,action,reason}`)
- `AI_STATE_PATH` (default `/data/ai/state.db`)
- `AI_MIN_SAMPLES`
- `AI_CHALLENGE_THRESHOLD`
- `AI_RATE_LIMIT_THRESHOLD`
- `AI_BLOCK_THRESHOLD`
- `AI_MAX_BODY_INSPECT_BYTES`
- `AI_COMMAND_TIMEOUT_MS`
- `AI_UPDATE_PROFILES_ON_BLOCK` (true/1)

Zero-config bootstrap:
- `PROTECT_DOMAINS` (comma-separated domains to auto-create routes for)
- `PROTECT_UPSTREAM` or `UPSTREAM` (single upstream, default `127.0.0.1:8080`)
- `PROTECT_UPSTREAMS` or `UPSTREAMS` (comma-separated upstream pool)
- `LB_POLICY` (`round_robin` or `least_conn`)
- `PROXY_MODE` (`standard` or `passthrough`)
- `DOH_EXCLUDE` (comma-separated hosts where `/dns-query` is bypassed from WAF/challenge)

## Notes

- Config loader supports `.yaml`, `.yml`, and `.json`.
- HTTP-01 challenges are served directly by the ACME handler and bypass challenge/rate-limit.
- DNS-01 mode uses external hook commands for issuance/renewal (compatible with `lego`/`certbot` workflows).
- Use a persistent volume mounted to `/data` to store ACME state.
- WAF uses anomaly-scoring with paranoia levels, rule actions (`score|log|allow|block`) and built-in signatures.
- AI engine stores adaptive request profiles in bbolt (`AI_STATE_PATH`) and can execute ONNX/TFLite inference through command hooks.
- `auto_shield.enabled: true` enables automatic behavior analysis + adaptive bans with safe defaults.

## DNS-01 Hook Example

```bash
ACME_DNS01=1 \
ACME_DNS_STORAGE=/data/acme/dns01 \
ACME_DNS_ISSUE_HOOK='lego --email ops@example.com --dns cloudflare --domains {domain} --path {storage} run && cp {storage}/certificates/{domain}.crt {cert} && cp {storage}/certificates/{domain}.key {key}' \
ACME_DNS_RENEW_HOOK='lego --email ops@example.com --dns cloudflare --domains {domain} --path {storage} renew --days 30 && cp {storage}/certificates/{domain}.crt {cert} && cp {storage}/certificates/{domain}.key {key}' \
./bin/astracat-protect -config configs/astra-dns.yaml -http :80 -https :443 -admin :9090
```

## AI Backend Commands

When `AI_BACKEND=onnx` or `AI_BACKEND=tflite`, command receives JSON on stdin and should return:

```json
{"score":8.4,"action":"block","reason":"onnx-runtime"}
```

## Custom TLS Certificates Per Domain

Use YAML and set TLS files under required host:

```yaml
servers:
  - hostname: panel.example.com
    tls:
      cert_file: /etc/ssl/panel.example.com/fullchain.pem
      key_file: /etc/ssl/panel.example.com/privkey.pem
    handles:
      - upstream: panel:3000
```

Behavior:
- If `servers[].tls` is set, this host uses your certificate via SNI.
- Hosts without `tls` continue to use ACME automatically.
- `acme.email` is required only for hosts that still use ACME.

## Auto Shield Per Domain

If you want protection only for selected domains:

```yaml
auto_shield:
  enabled: false # global default

servers:
  - hostname: panel.example.com
    auto_shield_enabled: true
    handles:
      - upstream: panel:3000

  - hostname: static.example.com
    auto_shield_enabled: false
    handles:
      - upstream: static:80
```


## Routing matchers

For `servers[].handles[].matcher` you can use one of:
- `path_exact` (exact match, e.g. `/dns-query`)
- `path_glob` (glob/prefix, e.g. `/api/*`)
- `path_regex` (Go regexp)

Evaluation priority: `path_exact` → `path_regex` → `path_glob`.

## Handle Upstream Pool

Per route handle you can define multi-upstream balancing and routing mode:

```yaml
servers:
  - hostname: api.example.com
    handles:
      - matcher_name: api
        matcher:
          path_glob: /api/*
        mode: standard
        lb_policy: least_conn
        upstreams:
          - api-1:8080
          - api-2:8080

  - hostname: doh.example.com
    handles:
      - matcher_name: doh
        matcher:
          path_exact: /dns-query
        mode: passthrough
        lb_policy: round_robin
        upstreams:
          - dnsdist-1:8053
          - dnsdist-2:8053
```
