// Package homelab_cloudflare adapts the retained Cloudflare middleware to a socket-peer
// trust boundary, with bounded synchronized refresh and a private origin token.
package homelab_cloudflare

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

const feedURL = "https://api.cloudflare.com/client/v4/ips"
const refreshInterval = 24 * time.Hour
const retryInterval = 5 * time.Minute
const maximumAge = 72 * time.Hour
const maximumBody = 65536
const originTokenFile = "/run/secrets/cloudflare-origin-token"

// Config declares explicit internal peers and the retained origin-header boundary.
type Config struct {
	InternalCIDRs []string `json:"internalCIDRs"`
	OriginHeader  string   `json:"originHeader"`
}

// CreateConfig starts without any implicit internal trust or origin credential.
func CreateConfig() *Config { return &Config{} }

// Cloudflare owns an isolated, synchronized address cache for one middleware.
type Cloudflare struct {
	next                     http.Handler
	internal                 []*net.IPNet
	header, token            string
	client                   *http.Client
	url                      string
	now                      func() time.Time
	refreshMu                sync.Mutex
	mu                       sync.RWMutex
	cidrs                    []*net.IPNet
	lastSuccess, nextRefresh time.Time
}

// New initializes bounded public trust while preserving internal access on feed failure.
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	token, err := readToken(originTokenFile)
	if err != nil {
		return nil, errors.New("invalid retained origin credential")
	}
	return newMiddleware(ctx, next, config, name, token)
}

// readToken reads only a bounded private regular file; the configured middleware never contains its value.
func readToken(path string) (string, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return "", errors.New("invalid origin credential file")
	}
	file, err := os.Open(path)
	if err != nil {
		return "", errors.New("unreadable origin credential file")
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, 4097))
	if err != nil || len(raw) < 16 || len(raw) > 4096 || len(strings.TrimSpace(string(raw))) == 0 || strings.ContainsAny(string(raw), "\r\n\x00") {
		return "", errors.New("invalid origin credential")
	}
	return string(raw), nil
}

// newMiddleware constructs the source boundary from already selected private bytes.
func newMiddleware(ctx context.Context, next http.Handler, config *Config, name, originToken string) (http.Handler, error) {
	if config == nil || len(config.InternalCIDRs) == 0 || len(config.InternalCIDRs) > 256 ||
		!validHeader(config.OriginHeader) || len(originToken) < 16 || len(originToken) > 4096 ||
		strings.ContainsAny(originToken, "\r\n\x00") {
		return nil, errors.New("invalid Cloudflare source configuration")
	}
	c := &Cloudflare{next: next, header: config.OriginHeader, token: originToken,
		url: feedURL, now: time.Now, client: &http.Client{Timeout: 5 * time.Second,
			CheckRedirect: func(r *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }}}
	for _, raw := range config.InternalCIDRs {
		ip, network, err := net.ParseCIDR(raw)
		if err != nil || ip.To4() == nil || !ip.IsPrivate() {
			return nil, errors.New("invalid internal source range")
		}
		bits, _ := network.Mask.Size()
		last := append(net.IP(nil), network.IP...)
		for i := range last {
			last[i] |= ^network.Mask[i]
		}
		if bits == 0 || !network.IP.IsPrivate() || !last.IsPrivate() {
			return nil, errors.New("invalid internal source range")
		}
		c.internal = append(c.internal, network)
	}
	// An initial feed outage must not take declared internal access down.
	c.refresh()
	return c, nil
}

// validHeader restricts the credential field without reusing identity headers.
func validHeader(value string) bool {
	if !strings.HasPrefix(value, "x-") || len(value) > 64 || value != strings.ToLower(value) {
		return false
	}
	for _, r := range value {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
			return false
		}
	}
	return !strings.HasPrefix(value, "x-forwarded-") && value != "x-real-ip"
}

// contains matches only a parsed socket or visitor address against selected networks.
func contains(networks []*net.IPNet, ip net.IP) bool {
	for _, network := range networks {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

// refresh serializes shared trust updates independently of visitor cancellation.
func (c *Cloudflare) refresh() {
	c.refreshMu.Lock()
	defer c.refreshMu.Unlock()
	now := c.now()
	c.mu.RLock()
	due := !now.Before(c.nextRefresh)
	c.mu.RUnlock()
	if !due {
		return
	}
	networks, err := c.fetch(context.Background())
	c.mu.Lock()
	defer c.mu.Unlock()
	if err != nil {
		c.nextRefresh = now.Add(retryInterval)
		log.Print("cloudflare-source: address refresh failed; public trust remains bounded by last successful fetch")
		return
	}
	// Keep separate assignments: the deployed Yaegi interpreter does not retain
	// every receiver field in this multiple-assignment form.
	c.cidrs = networks
	c.lastSuccess = now
	c.nextRefresh = now.Add(refreshInterval)
}

// fetch validates a bounded feed response using the client timeout and TLS policy.
func (c *Cloudflare) fetch(ctx context.Context) ([]*net.IPNet, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url, nil)
	if err != nil {
		return nil, err
	}
	response, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, errors.New("address feed status")
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maximumBody+1))
	if err != nil || len(body) > maximumBody {
		return nil, errors.New("address feed size")
	}
	var result struct {
		Success bool `json:"success"`
		Result  struct {
			IPv4 []string `json:"ipv4_cidrs"`
			IPv6 []string `json:"ipv6_cidrs"`
		} `json:"result"`
	}
	if json.Unmarshal(body, &result) != nil || !result.Success || len(result.Result.IPv4) == 0 ||
		len(result.Result.IPv6) == 0 || len(result.Result.IPv4)+len(result.Result.IPv6) > 256 {
		return nil, errors.New("invalid address feed")
	}
	networks := []*net.IPNet{}
	for family, rows := range [][]string{result.Result.IPv4, result.Result.IPv6} {
		for _, raw := range rows {
			ip, network, err := net.ParseCIDR(raw)
			if err != nil || !ip.IsGlobalUnicast() || ip.IsPrivate() {
				return nil, errors.New("invalid address range")
			}
			ones, bits := network.Mask.Size()
			if family == 0 && (bits != 32 || ones < 8) || family == 1 && (bits != 128 || ones < 16) || !ip.Equal(network.IP) {
				return nil, errors.New("invalid address range")
			}
			networks = append(networks, network)
		}
	}
	return networks, nil
}

// ServeHTTP authorizes the original peer before rebuilding trusted forwarding identity.
func (c *Cloudflare) ServeHTTP(w http.ResponseWriter, original *http.Request) {
	host, port, err := net.SplitHostPort(original.RemoteAddr)
	peer := net.ParseIP(host)
	if err != nil || peer == nil {
		http.Error(w, "invalid source", http.StatusBadRequest)
		return
	}
	r := original.Clone(original.Context())
	if contains(c.internal, peer) {
		scrub(r, c.header)
		r.Header.Set("X-Forwarded-For", peer.String())
		r.Header.Set("X-Real-IP", peer.String())
		scheme := "http"
		if r.TLS != nil {
			scheme = "https"
		}
		setOrigin(r, scheme)
		c.next.ServeHTTP(w, r)
		return
	}
	c.refresh()
	c.mu.RLock()
	available := len(c.cidrs) > 0 && c.now().Sub(c.lastSuccess) <= maximumAge
	trusted := contains(c.cidrs, peer)
	c.mu.RUnlock()
	if !available {
		http.Error(w, "source verification unavailable", http.StatusServiceUnavailable)
		return
	}
	if !trusted {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	tokens := r.Header.Values(c.header)
	if len(tokens) != 1 || subtle.ConstantTimeCompare([]byte(tokens[0]), []byte(c.token)) != 1 {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	visitors := r.Header.Values("CF-Connecting-IP")
	if len(visitors) != 1 || net.ParseIP(visitors[0]) == nil {
		http.Error(w, "invalid visitor", http.StatusBadRequest)
		return
	}
	visitor := net.ParseIP(visitors[0]).String()
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	values := r.Header.Values("CF-Visitor")
	if len(values) > 1 {
		http.Error(w, "invalid visitor", http.StatusBadRequest)
		return
	}
	if len(values) == 1 {
		var value struct {
			Scheme string `json:"scheme"`
		}
		if json.Unmarshal([]byte(values[0]), &value) != nil || (value.Scheme != "http" && value.Scheme != "https") {
			http.Error(w, "invalid visitor", http.StatusBadRequest)
			return
		}
		scheme = value.Scheme
	}
	scrub(r, c.header)
	r.Header.Set("X-Forwarded-For", visitor)
	r.Header.Set("X-Real-IP", visitor)
	setOrigin(r, scheme)
	r.RemoteAddr = net.JoinHostPort(visitor, port)
	c.next.ServeHTTP(w, r)
}

// scrub removes canonical and aliased identity/credential fields before forwarding.
func scrub(r *http.Request, tokenHeader string) {
	blocked := map[string]bool{}
	for _, name := range []string{"forwarded", "x-forwarded-for", "x-real-ip", "x-forwarded-proto",
		"x-forwarded-host", "x-forwarded-port", "cf-connecting-ip", "cf-connecting-ipv6", "cf-pseudo-ipv4", "cf-visitor", "true-client-ip", "x-client-ip", tokenHeader} {
		blocked[name] = true
	}
	for name := range r.Header {
		normalized := strings.NewReplacer("_", "-", ".", "-").Replace(strings.ToLower(name))
		if blocked[normalized] {
			delete(r.Header, name)
		}
	}
}

// setOrigin rebuilds forwarding origin from the validated scheme and routed Host.
func setOrigin(r *http.Request, scheme string) {
	r.Header.Set("X-Forwarded-Proto", scheme)
	r.Header.Set("X-Forwarded-Host", r.Host)
	port := "80"
	if scheme == "https" {
		port = "443"
	}
	if _, selected, err := net.SplitHostPort(r.Host); err == nil {
		port = selected
	}
	r.Header.Set("X-Forwarded-Port", port)
}
