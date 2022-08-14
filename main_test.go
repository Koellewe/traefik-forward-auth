package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	// "reflect"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

/**
 * Utilities
 */

type TokenServerHandler struct {
	ClientId string
	Roles    []string
}

func (t *TokenServerHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	payload := map[string]interface{}{}
	if t.ClientId != "" {
		clientData := map[string][]string{}
		clientData["roles"] = t.Roles
		resAccess := map[string]interface{}{}
		resAccess[t.ClientId] = clientData
		payload["resource_access"] = resAccess
	}

	payloadJsonBytes, err := json.Marshal(payload)
	if err != nil {
		panic(fmt.Sprintf("Failed to serve test access token because of a JSON marshalling problem: %v", err))
	}

	// header and sig are not checked
	fmt.Fprintf(w, `{"access_token":"header.%s.signature"}`, base64.RawStdEncoding.EncodeToString(payloadJsonBytes))
}

type UserServerHandler struct{}

func (t *UserServerHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, `{
    "id":"1",
    "email":"example@example.com",
    "verified_email":true,
    "hd":"example.com"
  }`)
}

func init() {
	log = CreateLogger("panic", "")
}

func httpRequest(r *http.Request, c *http.Cookie) (*http.Response, string) {
	w := httptest.NewRecorder()

	// Set cookies on recorder
	if c != nil {
		http.SetCookie(w, c)
	}

	// Copy into request
	for _, c := range w.HeaderMap["Set-Cookie"] {
		r.Header.Add("Cookie", c)
	}

	handler(w, r)

	res := w.Result()
	body, _ := ioutil.ReadAll(res.Body)

	return res, string(body)
}

func newHttpRequest(uri string) *http.Request {
	r := httptest.NewRequest("", "http://example.com", nil)
	r.Header.Add("X-Forwarded-Uri", uri)
	r.Header.Add("X-Forwarded-Proto", "http")
	r.Header.Add("X-Forwarded-Host", "example.com")
	return r
}

func qsDiff(one, two url.Values) {
	for k := range one {
		if two.Get(k) == "" {
			fmt.Printf("Key missing: %s\n", k)
		}
		if one.Get(k) != two.Get(k) {
			fmt.Printf("Value different for %s: expected: '%s' got: '%s'\n", k, one.Get(k), two.Get(k))
		}
	}
	for k := range two {
		if one.Get(k) == "" {
			fmt.Printf("Extra key: %s\n", k)
		}
	}
}

/**
 * Tests
 */

func TestHandler(t *testing.T) {
	fw = &ForwardAuth{
		Path:         "_oauth",
		ClientId:     "idtest",
		ClientSecret: "sectest",
		Scope:        "scopetest",
		LoginURL: &url.URL{
			Scheme: "http",
			Host:   "test.com",
			Path:   "/auth",
		},
		CookieName: "cookie_test",
		Lifetime:   time.Second * time.Duration(10),
	}

	// Should redirect vanilla request to login url
	req := newHttpRequest("foo")
	res, _ := httpRequest(req, nil)
	if res.StatusCode != 307 {
		t.Error("Vanilla request should be redirected with 307, got:", res.StatusCode)
	}
	fwd, _ := res.Location()
	if fwd.Scheme != "http" || fwd.Host != "test.com" || fwd.Path != "/auth" {
		t.Error("Vanilla request should be redirected to login url, got:", fwd)
	}

	// Should catch invalid cookie
	req = newHttpRequest("foo")

	c := fw.MakeCookie(req, "test@example.com")
	parts := strings.Split(c.Value, "|")
	c.Value = fmt.Sprintf("bad|%s|%s", parts[1], parts[2])

	res, _ = httpRequest(req, c)
	if res.StatusCode != 401 {
		t.Error("Request with invalid cookie shound't be authorised", res.StatusCode)
	}

	// Should validate email
	req = newHttpRequest("foo")

	c = fw.MakeCookie(req, "test@example.com")
	fw.Domain = []string{"test.com"}

	res, _ = httpRequest(req, c)
	if res.StatusCode != 401 {
		t.Error("Request with invalid cookie shound't be authorised", res.StatusCode)
	}

	// Should allow valid request email
	req = newHttpRequest("foo")

	c = fw.MakeCookie(req, "test@example.com")
	fw.Domain = []string{}

	res, _ = httpRequest(req, c)
	if res.StatusCode != 200 {
		t.Error("Valid request should be allowed, got:", res.StatusCode)
	}

	// Should pass through user
	users := res.Header["X-Forwarded-User"]
	if len(users) != 1 {
		t.Error("Valid request missing X-Forwarded-User header")
	} else if users[0] != "test@example.com" {
		t.Error("X-Forwarded-User should match user, got: ", users)
	}
}

func TestCallback(t *testing.T) {
	fw = &ForwardAuth{
		Path:         "_oauth",
		ClientId:     "idtest",
		ClientSecret: "sectest",
		Scope:        "scopetest",
		LoginURL: &url.URL{
			Scheme: "http",
			Host:   "test.com",
			Path:   "/auth",
		},
		CSRFCookieName: "csrf_test",
		RoleConfig:     nil,
	}

	// Setup token server
	tokenServerHandler := &TokenServerHandler{}
	tokenServer := httptest.NewServer(tokenServerHandler)
	defer tokenServer.Close()
	tokenUrl, _ := url.Parse(tokenServer.URL)
	fw.TokenURL = tokenUrl

	// Setup user server
	userServerHandler := &UserServerHandler{}
	userServer := httptest.NewServer(userServerHandler)
	defer userServer.Close()
	userUrl, _ := url.Parse(userServer.URL)
	fw.UserURL = userUrl

	// Should pass auth response request to callback
	req := newHttpRequest("_oauth")
	res, _ := httpRequest(req, nil)
	if res.StatusCode != 401 {
		t.Error("Auth callback without cookie shouldn't be authorised, got:", res.StatusCode)
	}

	// Should catch invalid csrf cookie
	req = newHttpRequest("_oauth?state=12345678901234567890123456789012:http://redirect")
	c := fw.MakeCSRFCookie(req, "nononononononononononononononono")
	res, _ = httpRequest(req, c)
	if res.StatusCode != 401 {
		t.Error("Auth callback with invalid cookie shouldn't be authorised, got:", res.StatusCode)
	}

	// Should redirect valid request
	req = newHttpRequest("_oauth?state=12345678901234567890123456789012:http://redirect")
	c = fw.MakeCSRFCookie(req, "12345678901234567890123456789012")
	res, _ = httpRequest(req, c)
	if res.StatusCode != 307 {
		t.Error("Valid callback should be allowed, got:", res.StatusCode)
	}
	fwd, _ := res.Location()
	if fwd.Scheme != "http" || fwd.Host != "redirect" || fwd.Path != "" {
		t.Error("Valid request should be redirected to return url, got:", fwd)
	}
}

func TestCallbackWithRoles(t *testing.T) {
	fw = &ForwardAuth{
		Path:         "/_oauth",
		ClientId:     "idtest",
		ClientSecret: "sectest",
		Scope:        "scopetest",
		LoginURL: &url.URL{
			Scheme: "http",
			Host:   "test.com",
			Path:   "/auth",
		},
		AuthHost:       "",
		CSRFCookieName: "csrf_test",
	}
	fw.SetRoleConfig(map[string][]string{
		"TEST_ROLE": {"example.com"},
	})

	// Setup token server
	tokenServerHandler := &TokenServerHandler{
		ClientId: "idtest",
		Roles:    []string{"TEST_ROLE", "OTHER_ROLE"},
	}
	tokenServer := httptest.NewServer(tokenServerHandler)
	tokenUrl, _ := url.Parse(tokenServer.URL)
	fw.TokenURL = tokenUrl

	// Setup user server
	userServerHandler := &UserServerHandler{}
	userServer := httptest.NewServer(userServerHandler)
	defer userServer.Close()
	userUrl, _ := url.Parse(userServer.URL)
	fw.UserURL = userUrl

	// Should redirect valid request
	req := newHttpRequest("/_oauth?state=12345678901234567890123456789012:http://redirect")
	c := fw.MakeCSRFCookie(req, "12345678901234567890123456789012")
	res, _ := httpRequest(req, c)
	if res.StatusCode != 307 {
		t.Error("Valid callback should be allowed, got:", res.StatusCode)
	}

	// Change token server to serve other roles
	tokenServerHandler.Roles = []string{"NON_APPLICABLE_ROLE"}
	// Should forbid valid req with bad roles in token
	res, _ = httpRequest(req, c)
	if res.StatusCode != 403 {
		t.Error("Valid callback with bad roles should be forbidden, got:", res.StatusCode)
	}
}
