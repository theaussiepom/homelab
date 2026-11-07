package homelab_cloudflare

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const validFeed = `{"success":true,"result":{"ipv4_cidrs":["173.245.48.0/20"],"ipv6_cidrs":["2400:cb00::/32"]}}`
const fixtureToken = "synthetic-origin-value-for-tests"

type transportFunc func(*http.Request) (*http.Response, error)

func (f transportFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func setup(t *testing.T, next http.Handler) *Cloudflare {
	t.Helper()
	previous := http.DefaultTransport
	http.DefaultTransport = transportFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(validFeed)), Header: http.Header{}}, nil
	})
	t.Cleanup(func() { http.DefaultTransport = previous })
	config := &Config{InternalCIDRs: []string{"10.0.0.0/8"}, OriginHeader: "x-origin-key", OriginToken: fixtureToken}
	handler, err := New(context.Background(), next, config, "fixture")
	if err != nil {
		t.Fatal(err)
	}
	c := handler.(*Cloudflare)
	// Retain the selected test transport after DefaultTransport is restored.
	c.client.Transport = http.DefaultTransport
	return c
}

func request(peer string) *http.Request {
	r := httptest.NewRequest("GET", "https://app.example.invalid/", nil)
	r.RemoteAddr = peer
	r.Header.Set("X-Origin-Key", fixtureToken)
	r.Header.Set("CF-Connecting-IP", "203.0.113.12")
	r.Header.Set("CF-Visitor", `{"scheme":"https"}`)
	r.Header.Set("X-Forwarded-For", "173.245.48.9, 10.0.0.1")
	r.Header.Set("X-Real-IP", "10.0.0.1")
	r.Header.Set("Forwarded", "for=10.0.0.1")
	r.Header.Set("X_Forwarded_For", "10.0.0.9")
	return r
}

func code(c *Cloudflare, r *http.Request) int {
	w := httptest.NewRecorder()
	c.ServeHTTP(w, r)
	return w.Code
}

func TestPeerBoundaryAndHeaders(t *testing.T) {
	var got *http.Request
	c := setup(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { got = r; w.WriteHeader(204) }))
	if code(c, request("203.0.113.2:1234")) != 403 {
		t.Fatal("forged XFF authorized an external peer")
	}
	if code(c, request("missing-port")) != 400 {
		t.Fatal("malformed peer")
	}
	r := request("173.245.48.9:1234")
	if code(c, r) != 204 || got.RemoteAddr != "203.0.113.12:1234" || got.Header.Get("X-Forwarded-For") != "203.0.113.12" ||
		got.Header.Get("X-Real-IP") != "203.0.113.12" || got.Header.Get("X-Forwarded-Proto") != "https" ||
		got.Header.Get("X-Origin-Key") != "" || got.Header.Get("Forwarded") != "" || got.Header.Get("CF-Connecting-IP") != "" {
		t.Fatal("Cloudflare visitor rewrite or token removal failed")
	}
	if r.Header.Get("X-Origin-Key") != fixtureToken || r.RemoteAddr != "173.245.48.9:1234" {
		t.Fatal("mutated original request")
	}
	r = request("10.0.0.2:1234")
	if code(c, r) != 204 || got.RemoteAddr != r.RemoteAddr || got.Header.Get("X-Forwarded-For") != "10.0.0.2" || got.Header.Get("X-Real-IP") != "10.0.0.2" || got.Header.Get("X-Forwarded-Proto") != "https" {
		t.Fatal("internal peer denied or rewritten")
	}
	for _, h := range []string{"X-Origin-Key", "CF-Visitor", "CF-Connecting-IP", "Forwarded", "X_Forwarded_For"} {
		if got.Header.Get(h) != "" {
			t.Fatal("internal spoof survived", h)
		}
	}
}

func TestHeaderNegativesAndIPv6(t *testing.T) {
	c := setup(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	for _, change := range []func(*http.Request){
		func(r *http.Request) { r.Header.Del("X-Origin-Key") },
		func(r *http.Request) { r.Header.Set("X-Origin-Key", "wrong") },
		func(r *http.Request) { r.Header.Add("X-Origin-Key", fixtureToken) },
	} {
		r := request("173.245.48.9:1234")
		change(r)
		if code(c, r) != 403 {
			t.Fatal("bad token accepted")
		}
	}
	for _, change := range []func(*http.Request){
		func(r *http.Request) { r.Header.Del("CF-Connecting-IP") },
		func(r *http.Request) { r.Header.Set("CF-Connecting-IP", "not-an-ip") },
		func(r *http.Request) { r.Header.Set("CF-Connecting-IP", "1.1.1.1,2.2.2.2") },
		func(r *http.Request) { r.Header.Add("CF-Connecting-IP", "1.1.1.1") },
		func(r *http.Request) { r.Header.Set("CF-Visitor", `{"scheme":"javascript"}`) },
		func(r *http.Request) { r.Header.Set("CF-Visitor", "invalid") },
		func(r *http.Request) { r.Header.Add("CF-Visitor", `{"scheme":"https"}`) },
	} {
		r := request("173.245.48.9:1234")
		change(r)
		if code(c, r) != 400 {
			t.Fatal("bad visitor accepted")
		}
	}
	r := request("[2400:cb00::1]:1234")
	r.Header.Set("CF-Connecting-IP", "2001:db8::1")
	if code(c, r) != 204 {
		t.Fatal("IPv6 Cloudflare denied")
	}
	r.Header.Del("CF-Visitor")
	r.TLS = &tls.ConnectionState{}
	if code(c, r) != 204 {
		t.Fatal("TLS fallback denied")
	}
	r.TLS = nil
	if code(c, r) != 204 {
		t.Fatal("HTTP fallback denied")
	}
}

func TestRefreshFailureStalenessAndConcurrency(t *testing.T) {
	c := setup(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	initial := c.lastSuccess
	c.now = func() time.Time { return initial.Add(25 * time.Hour) }
	var calls atomic.Int32
	c.client.Transport = transportFunc(func(r *http.Request) (*http.Response, error) {
		calls.Add(1)
		return &http.Response{StatusCode: 503, Body: io.NopCloser(strings.NewReader("unavailable"))}, nil
	})
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if code(c, request("173.245.48.9:1234")) != 204 {
				t.Error("last good ranges lost")
			}
		}()
	}
	wg.Wait()
	if calls.Load() != 1 {
		t.Fatal("refresh stampede", calls.Load())
	}
	c.now = func() time.Time { return initial.Add(73 * time.Hour) }
	if code(c, request("173.245.48.9:1234")) != 503 {
		t.Fatal("expired trust accepted")
	}
	if code(c, request("10.0.0.2:1234")) != 204 {
		t.Fatal("feed failure broke internal access")
	}
	c.cidrs = nil
	c.nextRefresh = time.Time{}
	if code(c, request("173.245.48.9:1234")) != 503 {
		t.Fatal("initial failure opened public access")
	}
	if code(c, request("10.0.0.2:1234")) != 204 {
		t.Fatal("initial failure broke internal access")
	}
}

func TestFeedRejectsInvalidReplacementAndHonorsCancellation(t *testing.T) {
	c := setup(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	for _, body := range []string{"invalid", `{"success":false}`, `{"success":true,"result":{"ipv4_cidrs":[],"ipv6_cidrs":[]}}`,
		strings.Replace(validFeed, "173.245.48.0/20", "0.0.0.0/0", 1), strings.Replace(validFeed, "173.245.48.0/20", "10.0.0.0/8", 1),
		strings.Replace(validFeed, "173.245.48.0/20", "173.245.48.1/20", 1), strings.Replace(validFeed, "2400:cb00::/32", "173.245.48.0/20", 1),
		strings.Repeat("x", maximumBody+1)} {
		c.client.Transport = transportFunc(func(r *http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body))}, nil
		})
		if _, err := c.fetch(context.Background()); err == nil {
			t.Fatal("invalid feed accepted")
		}
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	defer server.Close()
	c.client = &http.Client{Timeout: 20 * time.Millisecond, Transport: &http.Transport{}}
	c.url = server.URL
	start := time.Now()
	if _, err := c.fetch(context.Background()); err == nil || time.Since(start) > time.Second {
		t.Fatal("fetch timeout not bounded")
	}
}

func TestConfigRefusals(t *testing.T) {
	if CreateConfig() == nil {
		t.Fatal("default configuration")
	}
	for _, cfg := range []*Config{nil, {}, {InternalCIDRs: []string{"0.0.0.0/0"}, OriginHeader: "x-origin", OriginToken: fixtureToken},
		{InternalCIDRs: []string{"10.0.0.0/8"}, OriginHeader: "x-forwarded-for", OriginToken: fixtureToken},
		{InternalCIDRs: []string{"10.0.0.0/8"}, OriginHeader: "x-origin", OriginToken: "short"},
		{InternalCIDRs: []string{"bad"}, OriginHeader: "x-origin", OriginToken: fixtureToken},
		{InternalCIDRs: []string{"10.0.0.0/8"}, OriginHeader: "X-Origin", OriginToken: fixtureToken},
		{InternalCIDRs: []string{"10.0.0.0/8"}, OriginHeader: "x-origin!", OriginToken: fixtureToken}} {
		if _, err := New(context.Background(), http.NotFoundHandler(), cfg, "fixture"); err == nil {
			t.Fatal("invalid config accepted")
		}
	}
}
