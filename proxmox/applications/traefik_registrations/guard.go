// Package homelab_registrations protects administrative requests on a single Authentik router.
package homelab_registrations

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Config carries the JSON ownership projection intact through Traefik's file decoder.
type Config struct {
	Inventory string `json:"inventory"`
}
type ownership struct {
	Receipts []string          `json:"receipts,omitempty"`
	Active   map[string]string `json:"active,omitempty"`
	Retired  map[string]string `json:"retired,omitempty"`
}

func CreateConfig() *Config { return &Config{} }

type guard struct {
	next         http.Handler
	active       map[string]string
	slugs, names map[string]bool
	receipts     map[string]bool
}

var slugPattern = regexp.MustCompile("^[a-z0-9]+(-[a-z0-9]+)*$")
var uuidPattern = regexp.MustCompile("^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$")
var unavailable = errors.New("ownership could not be verified")
var protected = errors.New("registration managed in YAML")

const api = "/api/v3/"
const limit = 2 << 20

func New(_ context.Context, next http.Handler, cfg *Config, _ string) (http.Handler, error) {
	var declared ownership
	if cfg == nil || json.Unmarshal([]byte(cfg.Inventory), &declared) != nil || declared.Active == nil || declared.Retired == nil || declared.Receipts == nil {
		return nil, errors.New("missing Authentik registration inventory")
	}
	g := &guard{next: next, active: declared.Active, slugs: map[string]bool{}, names: map[string]bool{}, receipts: map[string]bool{}}
	for _, set := range []map[string]string{declared.Active, declared.Retired} {
		for slug, name := range set {
			if !slugPattern.MatchString(slug) || strings.TrimSpace(name) == "" || g.slugs[slug] || g.names[name] {
				return nil, errors.New("invalid Authentik registration identity")
			}
			g.slugs[slug] = true
			g.names[name] = true
		}
	}
	for _, name := range declared.Receipts {
		g.receipts[name] = true
	}
	return g, nil
}

// Read through the same router backend and transport as the original request. Only
// the caller's own credentials are used. Internal reads cannot choose a host,
// follow a redirect, return data to the caller or share a cache between sessions.
type response struct {
	header http.Header
	code   int
	data   bytes.Buffer
}

func (w *response) Flush() {
	if w.code == 0 {
		w.WriteHeader(200)
	}
}
func (w *response) Header() http.Header { return w.header }
func (w *response) WriteHeader(n int) {
	if w.code == 0 {
		w.code = n
	}
}
func (w *response) Write(p []byte) (int, error) {
	if w.code == 0 {
		w.WriteHeader(200)
	}
	if len(p) > limit-w.data.Len() {
		w.code = 503
		return 0, unavailable
	}
	return w.data.Write(p)
}
func (g *guard) read(r *http.Request, route string, result interface{}) error {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	u, err := url.ParseRequestURI(api + route)
	if err != nil {
		return unavailable
	}
	probe := r.Clone(ctx)
	probe.Method = http.MethodGet
	probe.URL = u
	probe.RequestURI = u.RequestURI()
	probe.Body = nil
	probe.GetBody = nil
	probe.ContentLength = 0
	probe.TransferEncoding = nil
	probe.Trailer = nil
	probe.Header = make(http.Header)
	probe.Header.Set("Accept", "application/json")
	for _, key := range []string{"Cookie", "Authorization"} {
		for _, value := range r.Header.Values(key) {
			probe.Header.Add(key, value)
		}
	}
	w := &response{header: make(http.Header)}
	g.next.ServeHTTP(w, probe)
	if ctx.Err() != nil || w.code != 200 || json.Unmarshal(w.data.Bytes(), result) != nil {
		return unavailable
	}
	return nil
}

type fields struct {
	Path        string            `json:"path"`
	Slug        string            `json:"slug"`
	Name        string            `json:"name"`
	Provider    json.RawMessage   `json:"provider"`
	Backchannel []json.RawMessage `json:"backchannel_providers"`
	Target      json.RawMessage   `json:"target"`
	Providers   []json.RawMessage `json:"providers"`
}

func body(r *http.Request, dst interface{}) error {
	if r.Body == nil || r.ContentLength == 0 {
		return nil
	}
	kind, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil {
		return protected
	}
	raw, err := savedBody(r)
	if err != nil {
		return err
	}
	if kind != "application/json" {
		return formFields(raw, kind, params, dst)
	}
	if !canonicalFields(raw, true) || json.Unmarshal(raw, dst) != nil {
		return protected
	}
	return nil
}

// The Authentik serializers select exact field names. Go normally matches
// struct fields case-insensitively. Reject ambiguous spelling before decoding.
func canonicalFields(raw []byte, transaction bool) bool {
	var object map[string]json.RawMessage
	if json.Unmarshal(raw, &object) != nil || object == nil {
		return false
	}
	for key, v := range object {
		switch strings.ToLower(key) {
		case "app", "slug", "name", "path", "target", "provider", "providers", "backchannel_providers":
			if key != strings.ToLower(key) {
				return false
			}
		}
		if transaction && (key == "app" || key == "provider") && bytes.HasPrefix(bytes.TrimSpace(v), []byte("{")) && !canonicalFields(v, false) {
			return false
		}
	}
	return true
}

func savedBody(r *http.Request) ([]byte, error) {
	if r.Body == nil || r.Header.Get("Content-Encoding") != "" {
		return nil, protected
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, limit+1))
	r.Body.Close()
	if err != nil || len(raw) > limit {
		return nil, protected
	}
	r.Body = io.NopCloser(bytes.NewReader(raw))
	return raw, nil
}

// For standard HTML forms, Django uses the final scalar and all values of
// list fields. Only the fields that select registration ownership are needed.
func formFields(raw []byte, kind string, params map[string]string, dst interface{}) error {
	values := url.Values{}
	switch kind {
	case "application/x-www-form-urlencoded":
		parsed, err := url.ParseQuery(string(raw))
		if err != nil {
			return protected
		}
		values = parsed
	case "multipart/form-data":
		reader := multipart.NewReader(bytes.NewReader(raw), params["boundary"])
		for {
			part, err := reader.NextPart()
			if err == io.EOF {
				break
			}
			if err != nil {
				return protected
			}
			if part.FormName() != "" && part.FileName() == "" {
				data, err := io.ReadAll(part)
				if err != nil {
					return protected
				}
				values.Add(part.FormName(), string(data))
			}
		}
	default:
		return protected
	}
	fields := map[string]interface{}{}
	app, provider := map[string]interface{}{}, map[string]interface{}{}
	for key, items := range values {
		dest := fields
		if strings.HasPrefix(key, "app.") {
			dest = app
			key = strings.TrimPrefix(key, "app.")
		}
		if strings.HasPrefix(key, "provider.") {
			dest = provider
			key = strings.TrimPrefix(key, "provider.")
		}
		switch key {
		case "slug", "name", "target", "path", "provider":
			dest[key] = items[len(items)-1]
		case "providers", "backchannel_providers":
			dest[key] = items
		default:
			if strings.HasPrefix(key, "providers[") || strings.HasPrefix(key, "backchannel_providers[") {
				return protected
			}
		}
	}
	if len(app) > 0 {
		fields["app"] = app
	}
	if len(provider) > 0 {
		fields["provider"] = provider
	}
	data, err := json.Marshal(fields)
	if err != nil || json.Unmarshal(data, dst) != nil {
		return protected
	}
	return nil
}

func (g *guard) blueprint(r *http.Request, id string) error {
	isManaged := func(f fields) bool {
		name := strings.TrimSuffix(strings.TrimPrefix(path.Clean(f.Path), "custom/"), ".yaml")
		return g.receipts[strings.TrimSpace(f.Name)] || (path.Clean(f.Path) == "custom/"+name+".yaml" && g.receipts[name])
	}
	if id != "" {
		if id == "import" {
			return nil
		}
		if !uuidPattern.MatchString(id) {
			return protected
		}
		var current fields
		if err := g.read(r, "managed/blueprints/"+id+"/", &current); err != nil || current.Name == "" {
			return unavailable
		}
		if isManaged(current) {
			return protected
		}
	}
	var proposed fields
	if err := body(r, &proposed); err != nil {
		return err
	}
	if isManaged(proposed) {
		return protected
	}
	return nil
}

func scalar(raw json.RawMessage) string {
	if len(raw) == 0 || string(raw) == "null" {
		return ""
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	return string(raw)
}
func (g *guard) provider(r *http.Request, id string) error {
	if id == "" {
		return nil
	}
	n, err := strconv.ParseUint(id, 10, 64)
	if err != nil || n == 0 {
		return protected
	}
	var p struct {
		PK   int    `json:"pk"`
		Name string `json:"name"`
		Slug string `json:"assigned_application_slug"`
		Back string `json:"assigned_backchannel_application_slug"`
	}
	if err := g.read(r, "providers/all/"+strconv.FormatUint(n, 10)+"/", &p); err != nil || p.PK <= 0 || uint64(p.PK) != n || p.Name == "" {
		return unavailable
	}
	if g.names[p.Name] || g.slugs[p.Slug] || g.slugs[p.Back] {
		return protected
	}
	return nil
}
func (g *guard) application(r *http.Request, a fields) error {
	if g.slugs[strings.TrimSpace(a.Slug)] {
		return protected
	}
	if len(a.Backchannel) > 256 {
		return unavailable
	}
	for _, ref := range append(a.Backchannel, a.Provider) {
		if err := g.provider(r, scalar(ref)); err != nil {
			return err
		}
	}
	return nil
}

// A binding serializer accepts either the native application ID or its policy
// target ID. Require a complete view of active YAML applications before allowing
// an unrelated binding change; a partial permission-filtered list proves nothing.
func uuidKey(s string) string {
	return strings.ToLower(strings.ReplaceAll(s, "-", ""))
}
func (g *guard) binding(r *http.Request, id string, intended json.RawMessage) error {
	targets := map[string]bool{}
	if intended != nil {
		targets[uuidKey(scalar(intended))] = true
	}
	if id != "" {
		if !uuidPattern.MatchString(id) {
			return protected
		}
		var b struct {
			Target json.RawMessage `json:"target"`
		}
		if err := g.read(r, "policies/bindings/"+id+"/", &b); err != nil || scalar(b.Target) == "" {
			return unavailable
		}
		targets[uuidKey(scalar(b.Target))] = true
	}
	found := map[string]bool{}
	for page := 1; page <= 32; page++ {
		var listing struct {
			Results []struct {
				Slug string `json:"slug"`
				PK   string `json:"pk"`
				PBM  string `json:"pbm_uuid"`
			} `json:"results"`
			Pagination struct {
				Current int `json:"current"`
				Next    int `json:"next"`
			} `json:"pagination"`
		}
		route := fmt.Sprintf("core/applications/?superuser_full_list=true&page_size=100&page=%d", page)
		if err := g.read(r, route, &listing); err != nil || listing.Results == nil || listing.Pagination.Current != page {
			return unavailable
		}
		for _, app := range listing.Results {
			if !g.slugs[app.Slug] {
				continue
			}
			if !uuidPattern.MatchString(app.PK) || !uuidPattern.MatchString(app.PBM) {
				return unavailable
			}
			if targets[uuidKey(app.PK)] || targets[uuidKey(app.PBM)] {
				return protected
			}
			if _, ok := g.active[app.Slug]; ok {
				found[app.Slug] = true
			}
		}
		if listing.Pagination.Next == 0 && len(found) == len(g.active) {
			return nil
		}
		if listing.Pagination.Next != page+1 {
			return unavailable
		}
	}
	return unavailable
}

// Inspect only the change in assigned providers. An unrelated provider can be
// added to or removed from the shared outpost without touching managed members.
func (g *guard) outpost(r *http.Request, id string, f fields) error {
	if r.Method != http.MethodDelete && f.Providers == nil {
		return nil
	}
	if len(f.Providers) > 256 {
		return unavailable
	}
	before := map[string]bool{}
	if id != "" {
		if !uuidPattern.MatchString(id) {
			return protected
		}
		var o fields
		if err := g.read(r, "outposts/instances/"+id+"/", &o); err != nil || o.Providers == nil || len(o.Providers) > 256 {
			return unavailable
		}
		for _, p := range o.Providers {
			before[scalar(p)] = true
		}
	}
	after := map[string]bool{}
	if r.Method != http.MethodDelete {
		for _, p := range f.Providers {
			after[scalar(p)] = true
		}
	}
	for p := range before {
		if !after[p] {
			if err := g.provider(r, p); err != nil {
				return err
			}
		}
	}
	for p := range after {
		if !before[p] {
			if err := g.provider(r, p); err != nil {
				return err
			}
		}
	}
	return nil
}

func (g *guard) check(r *http.Request) error {
	clean := path.Clean(r.URL.Path)
	if !strings.HasPrefix(clean, api) {
		return nil
	}
	parts := strings.Split(strings.TrimPrefix(clean, api), "/")
	if len(parts) < 2 {
		return nil
	}
	family := parts[0] + "/" + parts[1]
	id := ""
	if len(parts) > 2 {
		id = parts[2]
	}
	var f fields
	switch family {
	case "core/applications":
		if g.slugs[id] {
			return protected
		}
		if err := body(r, &f); err != nil {
			return err
		}
		return g.application(r, f)
	case "core/transactional":
		if id != "applications" {
			return nil
		}
		var tx struct {
			App      fields `json:"app"`
			Provider fields `json:"provider"`
		}
		if err := body(r, &tx); err != nil {
			return err
		}
		if g.names[strings.TrimSpace(tx.Provider.Name)] {
			return protected
		}
		return g.application(r, tx.App)
	case "providers/all", "providers/oauth2", "providers/proxy", "providers/saml":
		// Authentik's SAML metadata import creates a new provider.
		if family == "providers/saml" && id == "import_metadata" {
			if err := body(r, &f); err != nil {
				return err
			}
			if g.names[strings.TrimSpace(f.Name)] {
				return protected
			}
			return nil
		}
		if err := g.provider(r, id); err != nil {
			return err
		}
		if err := body(r, &f); err != nil {
			return err
		}
		if g.names[strings.TrimSpace(f.Name)] {
			return protected
		}
	case "managed/blueprints":
		return g.blueprint(r, id)
	case "policies/bindings":
		if err := body(r, &f); err != nil {
			return err
		}
		return g.binding(r, id, f.Target)
	case "outposts/instances":
		if err := body(r, &f); err != nil {
			return err
		}
		return g.outpost(r, id, f)
	}
	return nil
}
func (g *guard) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		g.next.ServeHTTP(w, r)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	inspected := r.WithContext(ctx)
	err := g.check(inspected)
	cancel()
	r.Body = inspected.Body
	if err == nil {
		g.next.ServeHTTP(w, r)
		return
	}
	code := http.StatusForbidden
	if err == unavailable {
		code = http.StatusServiceUnavailable
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"detail": err.Error()})
}
