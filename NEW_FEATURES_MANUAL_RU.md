# ASTRACAT PROTECT: Manual По Новым Функциям

Этот документ покрывает только новые возможности, добавленные в последних изменениях:
- `HTTP/3 (QUIC)`;
- `AI-WAF` с `builtin/onnx/tflite` backend;
- `DNS-01` автоматизация сертификатов через hooks;
- `Zero-config` env bootstrap;
- `per-domain`/`per-route` отключение защиты.

## 1) HTTP/3 (QUIC)

### Что это дает
- Поддержка `h3` поверх QUIC для клиентов/браузеров с HTTP/3.
- HTTPS и HTTP/3 работают параллельно.

### Конфиг (YAML)
```yaml
http3:
  enabled: true
  listen: ":443"
```

### Env
- `HTTP3_ENABLED=1`
- `HTTP3_LISTEN=:443`

### Проверка
```bash
curl --http3 -I https://example.com
```

---

## 2) AI-WAF (Adaptive + Hooks)

### Архитектура
- Встроенный адаптивный скоринг (`backend: builtin`) работает без внешних библиотек.
- Профили “нормального” трафика сохраняются в `bbolt` (`AI_STATE_PATH`).
- Для `onnx|tflite` используется hook-команда:
  - вход: JSON через `stdin`;
  - выход: JSON через `stdout` (`score`, `action`, `reason`).

### Конфиг (YAML)
```yaml
ai:
  enabled: true
  learning_mode: true
  backend: builtin # builtin | onnx | tflite
  model_path: /models/waf.onnx
  onnx_command: "python3 /app/ai-hooks/onnx_infer.py"
  tflite_command: "python3 /app/ai-hooks/tflite_infer.py"
  state_path: /data/ai/state.db
  min_samples: 50
  challenge_threshold: 5.0
  rate_limit_threshold: 7.0
  block_threshold: 9.0
  max_body_inspect_bytes: 8192
  command_timeout_ms: 25
  update_profiles_on_block: false
```

### Env
- `AI_ENABLED=1`
- `AI_LEARNING_MODE=1`
- `AI_BACKEND=builtin|onnx|tflite`
- `AI_MODEL_PATH=/models/waf.onnx`
- `AI_ONNX_COMMAND=...`
- `AI_TFLITE_COMMAND=...`
- `AI_STATE_PATH=/data/ai/state.db`
- `AI_MIN_SAMPLES=50`
- `AI_CHALLENGE_THRESHOLD=5`
- `AI_RATE_LIMIT_THRESHOLD=7`
- `AI_BLOCK_THRESHOLD=9`
- `AI_MAX_BODY_INSPECT_BYTES=8192`
- `AI_COMMAND_TIMEOUT_MS=25`

### Формат hook I/O
Вход (`stdin`):
```json
{
  "backend":"onnx",
  "model":"/models/waf.onnx",
  "host":"api.example.com",
  "method":"POST",
  "path":"/v1/login",
  "features":{
    "path_shape":"/v1/login",
    "path_length":9,
    "query_length":0,
    "header_count":12,
    "query_params":0,
    "body_length":423,
    "suspicious_hits":1
  }
}
```

Выход (`stdout`):
```json
{"score":8.4,"action":"block","reason":"onnx-runtime"}
```

Допустимые `action`:
- `allow`
- `challenge`
- `rate_limit`
- `block`

Если `action` не возвращать, решение принимается по threshold.

---

## 3) DNS-01 Автоматизация Сертификатов

### Что это
Вместо HTTP-01 можно включить DNS-01 через внешние hook-команды (например `lego`, `certbot`, внутренний скрипт).

### Конфиг (YAML)
```yaml
acme:
  email: ops@example.com
  storage_path: /data/acme
  on_demand_tls: true
  dns01_enabled: true
  dns_issue_hook: "lego ... {domain} ... --path {storage} ... && cp ... {cert} && cp ... {key}"
  dns_renew_hook: "lego ... renew ... {domain} ... --path {storage} ... && cp ... {cert} && cp ... {key}"
  dns_hook_timeout_seconds: 180
  dns_storage_path: /data/acme/dns01
```

### Env
- `ACME_DNS01=1`
- `ACME_DNS_ISSUE_HOOK='...'`
- `ACME_DNS_RENEW_HOOK='...'`
- `ACME_DNS_HOOK_TIMEOUT=180`
- `ACME_DNS_STORAGE=/data/acme/dns01`

### Подстановки в hook-командах
- `{domain}`: SNI домен
- `{storage}`: рабочая директория DNS-01
- `{cert}`: куда положить итоговый сертификат
- `{key}`: куда положить итоговый ключ

---

## 4) Zero-Config Bootstrap Через Env

### Назначение
Если не хотите сразу писать полный `servers[]`, можно собрать маршруты только через env.

### Минимальный набор
```bash
PROTECT_DOMAINS="example.com,api.example.com"
PROTECT_UPSTREAMS="app-1:8080,app-2:8080"
LB_POLICY="least_conn"
PROXY_MODE="standard"
SSL_MODE="internal"
```

### Полезно
- `DOH_EXCLUDE="doh.example.com"` — облегченный bypass для DoH endpoint.

---

## 5) Как Выключить Защиту Для Домена

Есть несколько уровней “выключения”:

### 5.1 Отключить Auto Shield только для домена
```yaml
servers:
  - hostname: static.example.com
    auto_shield_enabled: false
```

### 5.2 Отключить WAF для домена
```yaml
waf:
  exempt_hosts:
    - static.example.com
```

### 5.3 Убрать challenge для домена/пути
- challenge сейчас исключается по путям (`challenge.exempt_globs`), не по host.
- для домена с особыми endpoint обычно делают route `mode: passthrough`.

### 5.4 Полный bypass защиты на route
```yaml
servers:
  - hostname: static.example.com
    handles:
      - mode: passthrough
        upstream: static:80
```

`passthrough` отключает для этого маршрута защитный pipeline (WAF/challenge/rate/risk/auto-shield).

---

## 6) Балансировка Upstream

Поддерживаемые политики:
- `round_robin`
- `least_conn`

Пример:
```yaml
servers:
  - hostname: api.example.com
    handles:
      - lb_policy: least_conn
        upstreams:
          - api-1:8080
          - api-2:8080
          - api-3:8080
```

---

## 7) Быстрый Docker Рецепт (ONNX)

```bash
docker build -f Dockerfile.ai -t astracat/protect:ai .

docker run -d --name astracat-protect \
  -p 80:80 -p 443:443 -p 127.0.0.1:9091:9090 \
  -v /opt/astracat-protect/configs:/app/configs:ro \
  -v /opt/astracat-protect/data:/data \
  -v /opt/astracat-protect/models:/models:ro \
  -e ADMIN_TOKEN=changeme \
  -e ACME_EMAIL=ops@example.com \
  -e HTTP3_ENABLED=1 \
  -e AI_ENABLED=1 \
  -e AI_BACKEND=onnx \
  -e AI_MODEL_PATH=/models/waf.onnx \
  -e AI_ONNX_COMMAND='python3 /app/ai-hooks/onnx_infer.py' \
  astracat/protect:ai \
  -config /app/configs/astra.yaml -http :80 -https :443 -admin :9090
```

---

## 8) Эксплуатационные Рекомендации

- Храните `/data` на persistent volume.
- Сначала запускайте AI в `learning_mode: true`, потом включайте строгий enforcement.
- Для DNS-01 делайте hooks идемпотентными и с retry.
- Для низкорисковых доменов используйте `passthrough`, но только осознанно.
- Проверяйте `/metrics` и логи после каждого изменения.

---

## 9) Где Смотреть Дополнительно

- Docker + AI: `DOCKER_AI_MANUAL_RU.md`
- Общий deploy: `DOCKER_DEPLOY.md`
- Общий manual: `MANUAL_RU.md`
