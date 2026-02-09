package challenge

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

type RiskEntry struct {
	Score            int
	Last             time.Time
	ErrorCount       int
	ErrorWindowStart time.Time
}

type RiskTracker struct {
	mu           sync.Mutex
	entries      map[string]*RiskEntry
	threshold    int
	statusWindow time.Duration
	ttl          time.Duration
}

func NewRiskTracker(threshold int, statusWindow, ttl time.Duration) *RiskTracker {
	return &RiskTracker{
		entries:      map[string]*RiskEntry{},
		threshold:    threshold,
		statusWindow: statusWindow,
		ttl:          ttl,
	}
}

func (rt *RiskTracker) UpdateRequest(ip string, r *http.Request) {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	e := rt.get(ip)
	e.Last = time.Now()
	if r.UserAgent() == "" {
		e.Score++
	}
	if r.Header.Get("Accept") == "" || r.Header.Get("Accept-Language") == "" {
		e.Score++
	}
}

func (rt *RiskTracker) UpdateStatus(ip string, status int) {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	e := rt.get(ip)
	now := time.Now()
	if e.ErrorWindowStart.IsZero() || now.Sub(e.ErrorWindowStart) > rt.statusWindow {
		e.ErrorWindowStart = now
		e.ErrorCount = 0
	}
	if status >= 400 {
		e.ErrorCount++
	}
	if e.ErrorCount > 10 {
		e.Score++
	}
	e.Last = now
}

func (rt *RiskTracker) Penalize(ip string, score int) {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	e := rt.get(ip)
	e.Score += score
	e.Last = time.Now()
}

func (rt *RiskTracker) Allowed(ip string) bool {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	e := rt.entries[ip]
	if e == nil {
		return true
	}
	return e.Score < rt.threshold
}

func (rt *RiskTracker) Cleanup() {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	now := time.Now()
	for k, v := range rt.entries {
		if now.Sub(v.Last) > rt.ttl {
			delete(rt.entries, k)
		}
	}
}

func (rt *RiskTracker) get(ip string) *RiskEntry {
	e := rt.entries[ip]
	if e == nil {
		e = &RiskEntry{Last: time.Now()}
		rt.entries[ip] = e
	}
	return e
}

type Manager struct {
	Secret          []byte
	CookieName      string
	CookieTTL       time.Duration
	BindIP          bool
	BindUA          bool
	VerifyPath      string
	InterstitialURI string
}

func NewManager(secret []byte, ttl time.Duration) *Manager {
	return &Manager{
		Secret:          secret,
		CookieName:      "astracat_clearance",
		CookieTTL:       ttl,
		VerifyPath:      "/__challenge/verify",
		InterstitialURI: "/__challenge",
	}
}

func (m *Manager) CookieValue(ip, ua string, expiry time.Time) string {
	payload := fmt.Sprintf("%d", expiry.Unix())
	if m.BindIP {
		payload += "|" + ip
	}
	if m.BindUA {
		payload += "|" + ua
	}

	mac := hmac.New(sha256.New, m.Secret)
	mac.Write([]byte(payload))
	sig := mac.Sum(nil)
	return base64.RawURLEncoding.EncodeToString([]byte(payload)) + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func (m *Manager) VerifyCookie(ip, ua string, value string) bool {
	parts := strings.Split(value, ".")
	if len(parts) != 2 {
		return false
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return false
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, m.Secret)
	mac.Write(payloadBytes)
	if !hmac.Equal(sig, mac.Sum(nil)) {
		return false
	}
	payload := string(payloadBytes)
	fields := strings.Split(payload, "|")
	if len(fields) == 0 {
		return false
	}
	exp, err := parseInt64(fields[0])
	if err != nil {
		return false
	}
	if time.Now().Unix() > exp {
		return false
	}
	idx := 1
	if m.BindIP {
		if idx >= len(fields) || fields[idx] != ip {
			return false
		}
		idx++
	}
	if m.BindUA {
		if idx >= len(fields) || fields[idx] != ua {
			return false
		}
	}
	return true
}

func (m *Manager) InterstitialHTML(original string) string {
	encoded := url.QueryEscape(original)
	return fmt.Sprintf(`<!doctype html>
<html>
<head>
<meta charset="utf-8" />
<title>Checking your browser...</title>
<style>
body{font-family:Arial,sans-serif;background:#0b0c10;color:#fff;display:flex;align-items:center;justify-content:center;height:100vh;margin:0}
.card{background:#1f2833;padding:24px 32px;border-radius:10px;box-shadow:0 10px 30px rgba(0,0,0,.3)}
.spinner{width:26px;height:26px;border:3px solid #45a29e;border-top-color:transparent;border-radius:50%;animation:spin 1s linear infinite;display:inline-block;margin-right:12px}
@keyframes spin{to{transform:rotate(360deg)}}
</style>
</head>
<body>
<div class="card"><span class="spinner"></span>Checking your browser...</div>
<script>
setTimeout(function(){
  window.location.href = "%s?url=%s";
}, 3000);
</script>
</body>
</html>`, m.VerifyPath, encoded)
}

func parseInt64(s string) (int64, error) {
	var v int64
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, fmt.Errorf("invalid int")
		}
		v = v*10 + int64(r-'0')
	}
	return v, nil
}
