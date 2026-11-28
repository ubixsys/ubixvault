package api

import (
	"net/http"
	"testing"
)

type mountForPathResponse struct {
	Data struct {
		Path    string            `json:"path"`
		Type    string            `json:"type"`
		Options map[string]string `json:"options"`
	} `json:"data"`
}

// The vault/bao CLIs' `kv` commands ask this before every KV call; a 404 makes
// them treat secret/ as KV version 1 and fail.
func TestUIMountForPath_KVv2(t *testing.T) {
	h, root := unsealedHandler(t)
	for _, p := range []string{"secret/app/db", "secret/app", "secret", "secret/"} {
		rec := doAuth(t, h, "GET", "/v1/sys/internal/ui/mounts/"+p, "", root)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: code = %d, body=%s", p, rec.Code, rec.Body.String())
		}
		resp := decode[mountForPathResponse](t, rec)
		if resp.Data.Path != "secret/" || resp.Data.Type != "kv" || resp.Data.Options["version"] != "2" {
			t.Fatalf("%s: got path=%q type=%q options=%v", p, resp.Data.Path, resp.Data.Type, resp.Data.Options)
		}
	}
}

func TestUIMountForPath_OtherEngines(t *testing.T) {
	h, root := unsealedHandler(t)
	for p, want := range map[string]string{"transit/keys/a": "transit", "database/creds/r": "database", "pki/issue/r": "pki", "cubbyhole/x": "cubbyhole"} {
		resp := decode[mountForPathResponse](t, doAuth(t, h, "GET", "/v1/sys/internal/ui/mounts/"+p, "", root))
		if resp.Data.Type != want {
			t.Errorf("%s: type = %q, want %q", p, resp.Data.Type, want)
		}
	}
}

// A token that may only read secret/data/app/* must get the answer for
// secret/app/..., or its `kv get` fails before it starts.
func TestUIMountForPath_TokenWithAccessInTheMount(t *testing.T) {
	h, root := unsealedHandler(t)
	doc := `{"path":{"secret/data/app/*":{"capabilities":["read"]}}}`
	if rec := doAuth(t, h, "PUT", "/v1/sys/policies/acl/app-reader", doc, root); rec.Code != http.StatusNoContent {
		t.Fatalf("write policy = %d, body=%s", rec.Code, rec.Body.String())
	}
	tok := createToken(t, h, root, `["app-reader"]`)
	rec := doAuth(t, h, "GET", "/v1/sys/internal/ui/mounts/secret/app/db", "", tok)
	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d, body=%s", rec.Code, rec.Body.String())
	}
	if got := decode[mountForPathResponse](t, rec).Data.Options["version"]; got != "2" {
		t.Fatalf("version = %q", got)
	}
}

func TestUIMountForPath_Refusals(t *testing.T) {
	h, root := unsealedHandler(t)
	noAccess := createToken(t, h, root, `["default"]`)
	denyDoc := `{"path":{"secret/*":{"capabilities":["deny"]},"secret/data/app/*":{"capabilities":["read"]}}}`
	if rec := doAuth(t, h, "PUT", "/v1/sys/policies/acl/denied", denyDoc, root); rec.Code != http.StatusNoContent {
		t.Fatalf("write policy = %d, body=%s", rec.Code, rec.Body.String())
	}
	denied := createToken(t, h, root, `["denied"]`)
	cases := []struct {
		name, path, token string
		want              int
	}{
		{"no token", "secret/app", "", http.StatusUnauthorized},
		{"unknown token", "secret/app", "uv.not-a-token", http.StatusForbidden},
		{"no access in the mount", "secret/app", noAccess, http.StatusForbidden},
		{"not a mount", "nothing/here", root, http.StatusNotFound},
		{"grant covered by a deny on the mount", "secret/app", denied, http.StatusForbidden},
	}
	for _, c := range cases {
		if rec := doAuth(t, h, "GET", "/v1/sys/internal/ui/mounts/"+c.path, "", c.token); rec.Code != c.want {
			t.Errorf("%s: code = %d, want %d, body=%s", c.name, rec.Code, c.want, rec.Body.String())
		}
	}
	// Every token has its own cubbyhole.
	if rec := doAuth(t, h, "GET", "/v1/sys/internal/ui/mounts/cubbyhole/x", "", noAccess); rec.Code != http.StatusOK {
		t.Errorf("cubbyhole: code = %d, body=%s", rec.Code, rec.Body.String())
	}
}

func TestUIMountForPath_Sealed(t *testing.T) {
	h, root := unsealedHandler(t)
	doAuth(t, h, "POST", "/v1/sys/seal", "", root)
	if rec := doAuth(t, h, "GET", "/v1/sys/internal/ui/mounts/secret/app", "", root); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("code = %d, want 503", rec.Code)
	}
}

// The existing sign-in list at the bare path is unchanged.
func TestUIMountForPath_BarePathStillListsSignInMethods(t *testing.T) {
	h, _ := unsealedHandler(t)
	if paths := uiAuthPaths(t, h); len(paths) == 0 {
		t.Fatal("no sign-in methods listed")
	}
}

func TestSysMounts(t *testing.T) {
	h, root := unsealedHandler(t)
	rec := doAuth(t, h, "GET", "/v1/sys/mounts", "", root)
	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d, body=%s", rec.Code, rec.Body.String())
	}
	resp := decode[struct {
		Data map[string]mountInfo `json:"data"`
	}](t, rec)
	if m := resp.Data["secret/"]; m.Type != "kv" || m.Options["version"] != "2" {
		t.Fatalf("secret/ = %+v", m)
	}
	for _, p := range []string{"cubbyhole/", "transit/", "database/", "pki/", "identity/"} {
		if _, ok := resp.Data[p]; !ok {
			t.Errorf("%s missing", p)
		}
	}
	noAccess := createToken(t, h, root, `["default"]`)
	if rec := doAuth(t, h, "GET", "/v1/sys/mounts", "", noAccess); rec.Code != http.StatusForbidden {
		t.Fatalf("without read on sys/mounts: code = %d, want 403", rec.Code)
	}
}
