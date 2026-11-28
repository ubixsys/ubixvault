package api

import (
	"net/http"
	"sort"
	"testing"
)

type uiMountsResponse struct {
	Data struct {
		Auth   map[string]uiMount `json:"auth"`
		Secret map[string]uiMount `json:"secret"`
	} `json:"data"`
}

func uiAuthPaths(t *testing.T, h http.Handler) []string {
	t.Helper()
	expireUIMounts(h)
	rec := do(t, h, "GET", "/v1/sys/internal/ui/mounts", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("ui mounts = %d, body=%s", rec.Code, rec.Body.String())
	}
	resp := decode[uiMountsResponse](t, rec)
	if len(resp.Data.Secret) != 0 {
		t.Fatalf("secret engines listed without a token: %v", resp.Data.Secret)
	}
	var paths []string
	for p, m := range resp.Data.Auth {
		if m.Type+"/" != p {
			t.Errorf("mount %q has type %q", p, m.Type)
		}
		paths = append(paths, p)
	}
	sort.Strings(paths)
	return paths
}

func TestUIMountsListsOnlyConfiguredSignInMethods(t *testing.T) {
	h, root := unsealedHandler(t)

	if got := uiAuthPaths(t, h); len(got) != 1 || got[0] != "token/" {
		t.Fatalf("fresh vault = %v, want only token/", got)
	}

	if rec := doAuth(t, h, "POST", "/v1/auth/userpass/users/alice", `{"password":"pw-1234567","policies":["default"]}`, root); rec.Code != http.StatusNoContent {
		t.Fatalf("create user = %d, body=%s", rec.Code, rec.Body.String())
	}
	if got := uiAuthPaths(t, h); len(got) != 2 || got[0] != "token/" || got[1] != "userpass/" {
		t.Fatalf("with a user = %v, want token/ and userpass/", got)
	}

	if rec := doAuth(t, h, "POST", "/v1/auth/ldap/config",
		`{"url":"ldap://dir.test:389","user_dn":"ou=people,dc=test"}`, root); rec.Code != http.StatusNoContent {
		t.Fatalf("configure ldap = %d, body=%s", rec.Code, rec.Body.String())
	}
	if got := uiAuthPaths(t, h); len(got) != 3 || got[0] != "ldap/" {
		t.Fatalf("with ldap = %v, want ldap/, token/, userpass/", got)
	}

	// Machine methods stay unlisted even once they hold roles.
	if rec := doAuth(t, h, "POST", "/v1/auth/approle/role/ci", `{"token_policies":["default"]}`, root); rec.Code != http.StatusNoContent {
		t.Fatalf("create approle role = %d, body=%s", rec.Code, rec.Body.String())
	}
	if got := uiAuthPaths(t, h); len(got) != 3 {
		t.Fatalf("approle should not be listed: %v", got)
	}
}

func TestUIMountsSealed(t *testing.T) {
	h := newTestHandler()
	do(t, h, "POST", "/v1/sys/init", `{"secret_shares":2,"secret_threshold":2}`)
	if rec := do(t, h, "GET", "/v1/sys/internal/ui/mounts", ""); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("sealed = %d, want 503 (body=%s)", rec.Code, rec.Body.String())
	}
}

// expireUIMounts drops the cached answer so a test sees a change at once.
func expireUIMounts(h http.Handler) {
	if hh, ok := h.(*Handler); ok {
		hh.signInCache.mu.Lock()
		hh.signInCache.auth = nil
		hh.signInCache.mu.Unlock()
	}
}

func TestUIMountsIsCached(t *testing.T) {
	h, root := unsealedHandler(t)
	if got := uiAuthPaths(t, h); len(got) != 1 {
		t.Fatalf("fresh vault = %v", got)
	}
	doAuth(t, h, "POST", "/v1/auth/userpass/users/bob", `{"password":"pw-1234567","policies":["default"]}`, root)
	rec := do(t, h, "GET", "/v1/sys/internal/ui/mounts", "")
	if resp := decode[uiMountsResponse](t, rec); len(resp.Data.Auth) != 1 {
		t.Fatalf("within the TTL the cached answer should be served, got %v", resp.Data.Auth)
	}
}
