package homelab_registrations

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const appID = "0177a17a-3512-49ef-b029-d7a15eaba15c"
const other = "79fa235f-5714-4c35-a981-8fa8f5fa2ceb"
const bindingID = "d45ebce2-d4d3-4d93-88b2-86a0870123f2"

func TestAdminAndSignIn(t *testing.T) {
	config := CreateConfig()
	config.Inventory = `{"active":{"editor":"Editor"},"retired":{"old-editor":"Old"},"receipts":["homelab-oidc-editor"]}`
	cases := []struct {
		method, route, body string
		status              int
	}{
		{"GET", "core/applications/editor/", "", 204}, {"PATCH", "core/applications/editor/", `{"name":"New"}`, 403},
		{"DELETE", "core/applications/editor/", "", 403}, {"POST", "core/applications/", `{"slug":"old-editor"}`, 403},
		{"PATCH", "core/applications/unmanaged/", `{"name":"New"}`, 204}, {"POST", "core/applications/", `{"slug":"lab","provider":7}`, 403},
		{"POST", "core/applications/", `{"slug":"lab","backchannel_providers":[8]}`, 204},
		{"PUT", "core/transactional/applications/", `{"app":{"slug":"editor"},"provider":{"name":"unmanaged"}}`, 403},
		{"PUT", "core/transactional/applications/", `{"app":{"slug":"unmanaged"},"provider":{"name":"Editor"}}`, 403},
		{"PUT", "core/transactional/applications/", `{"app":{"slug":"lab"},"provider":{"name":"Lab"}}`, 204},
		{"DELETE", "providers/all/7/", "", 403}, {"PATCH", "providers/proxy/7/", `{"name":"New"}`, 403},
		{"PUT", "providers/saml/7/", `{"name":"New"}`, 403}, {"PATCH", "providers/oauth2/8/", `{"name":"New"}`, 204},
		{"POST", "providers/oauth2/", `{"name":"Editor"}`, 403}, {"POST", "providers/oauth2/", `{"name":"Lab"}`, 204},
		{"PATCH", "providers/oauth2/9/", `{}`, 503},
		{"DELETE", "policies/bindings/" + bindingID + "/", "", 403},
		{"PATCH", "policies/bindings/" + bindingID + "/", fmt.Sprintf(`{"target":%q}`, other), 403},
		{"PATCH", "policies/bindings/" + other + "/", fmt.Sprintf(`{"target":%q}`, appID), 403},
		{"POST", "policies/bindings/", fmt.Sprintf(`{"target":%q}`, strings.ReplaceAll(appID, "-", "")), 403},
		{"POST", "policies/bindings/", fmt.Sprintf(`{"target":%q}`, other), 204},
		{"DELETE", "policies/bindings/" + other + "/", "", 204},
		{"DELETE", "outposts/instances/" + other + "/", "", 403},
		{"PATCH", "outposts/instances/" + other + "/", `{"providers":[8]}`, 403},
		{"PATCH", "outposts/instances/" + other + "/", `{"providers":[7,8]}`, 204},
		{"POST", "outposts/instances/", `{"providers":[7]}`, 403},
		{"PATCH", "outposts/instances/" + other + "/", `{"name":"New"}`, 204},
		{"PATCH", "managed/blueprints/" + other + "/", `{"enabled":false}`, 403},
		{"POST", "managed/blueprints/" + other + "/apply/", "", 403},
		{"POST", "managed/blueprints/", `{"name":"duplicate","path":"custom/homelab-oidc-editor.yaml"}`, 403},
		{"POST", "managed/blueprints/", `{"name":"independent"}`, 204},
		{"PATCH", "core/users/12/", `{"name":"New"}`, 204},
		{"POST", "flows/executor/login/", `{"stage":"continue"}`, 204},
		{"POST", "/application/o/token/", "token request", 204}, {"POST", "/application/saml/editor/sso/binding/post/", "SAML form", 204},
	}
	for _, c := range cases {
		t.Run(c.method+" "+c.route, func(t *testing.T) {
			location := api + c.route
			if strings.HasPrefix(c.route, "/") {
				location = c.route
			}
			forwarded := 0
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == location && r.Method == c.method {
					forwarded++
					b, _ := io.ReadAll(r.Body)
					if string(b) != c.body {
						t.Errorf("body changed: %q", b)
					}
					w.WriteHeader(204)
					return
				}
				if r.Method != "GET" || r.Header.Get("Cookie") != "fixture=admin" || r.Header.Get("X-Unrelated") != "" || r.Header.Get("Accept") != "application/json" {
					t.Fatal("unexpected lookup")
				}
				switch r.URL.Path {
				case api + "providers/all/7/":
					fmt.Fprint(w, `{"pk":7,"name":"Editor","assigned_application_slug":"editor"}`)
				case api + "providers/all/8/":
					fmt.Fprint(w, `{"pk":8,"name":"Lab"}`)
				case api + "core/applications/":
					if r.URL.Query().Get("superuser_full_list") != "true" {
						t.Fatal("list scope")
					}
					fmt.Fprintf(w, `{"results":[{"slug":"editor","pk":%q,"pbm_uuid":%q}],"pagination":{"current":1,"next":0}}`, appID, appID)
				case api + "policies/bindings/" + bindingID + "/":
					fmt.Fprintf(w, `{"target":%q}`, appID)
				case api + "policies/bindings/" + other + "/":
					fmt.Fprintf(w, `{"target":%q}`, other)
				case api + "outposts/instances/" + other + "/":
					fmt.Fprint(w, `{"providers":[7]}`)
				case api + "managed/blueprints/" + other + "/":
					fmt.Fprint(w, `{"name":"homelab-oidc-editor"}`)
				default:
					w.WriteHeader(404)
				}
			})
			guard, err := New(context.Background(), next, config, "fixture")
			if err != nil {
				t.Fatal(err)
			}
			r := httptest.NewRequest(c.method, location, strings.NewReader(c.body))
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("Cookie", "fixture=admin")
			r.Header.Set("X-Unrelated", "remove")
			w := httptest.NewRecorder()
			guard.ServeHTTP(w, r)
			if w.Code != c.status || (c.status == 204) != (forwarded == 1) {
				t.Errorf("status %d, writes %d, expected %d", w.Code, forwarded, c.status)
			}
		})
	}
}
func TestMetadataAndIncompleteOwnership(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			fmt.Fprint(w, `{"results":[],"pagination":{"current":1,"next":0}}`)
			return
		}
		w.WriteHeader(204)
	})
	g, err := New(context.Background(), next, &Config{Inventory: `{"active":{"managed":"Managed"},"retired":{},"receipts":[]}`}, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"Managed", "Independent"} {
		var data bytes.Buffer
		form := multipart.NewWriter(&data)
		form.WriteField("name", name)
		form.Close()
		r := httptest.NewRequest("POST", api+"providers/saml/import_metadata/", &data)
		r.Header.Set("Content-Type", form.FormDataContentType())
		w := httptest.NewRecorder()
		g.ServeHTTP(w, r)
		if (w.Code == 204) != (name == "Independent") || (w.Code == 403) != (name == "Managed") {
			t.Fatal(w.Code)
		}
	}
	r := httptest.NewRequest("POST", api+"policies/bindings/", strings.NewReader(fmt.Sprintf(`{"target":%q}`, other)))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	g.ServeHTTP(w, r)
	if w.Code != 503 {
		t.Fatal(w.Code)
	}
}

func TestManagementForms(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.Header.Get("Content-Type"), "application/x-www-form-urlencoded") {
			if err := r.ParseForm(); err != nil || r.Form.Get("name") != "Independent" {
				t.Fatal("form changed")
			}
		}
		w.WriteHeader(204)
	})
	g, err := New(context.Background(), next, &Config{Inventory: `{"active":{"managed":"Managed"},"retired":{},"receipts":[]}`}, "fixture")
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		content, body string
		status        int
	}{
		{"application/x-www-form-urlencoded", "name=Managed", 403},
		{"application/x-www-form-urlencoded", "name=Independent", 204},
		{"application/json", `{"name":" Managed "}`, 403},
		{"application/json", `{"name":"Independent"}`, 204},
		{"application/json", "invalid-json", 403},
		{"text/plain", "name=Independent", 403},
	} {
		r := httptest.NewRequest("POST", api+"providers/oauth2/", strings.NewReader(test.body))
		r.Header.Set("Content-Type", test.content)
		w := httptest.NewRecorder()
		g.ServeHTTP(w, r)
		if w.Code != test.status {
			t.Errorf("%s: got %d, want %d", test.content, w.Code, test.status)
		}
	}
}
