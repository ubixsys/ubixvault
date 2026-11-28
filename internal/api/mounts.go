package api

import (
	"errors"
	"net/http"
	"strings"

	"github.com/cwolsen7905/ubixvault/internal/barrier"
	"github.com/cwolsen7905/ubixvault/internal/token"
)

// mountInfo is one secrets engine mount in Vault's sys/mounts shape.
//
// uBixVault has no `secrets enable`: its engines sit at fixed paths. Vault's
// clients still ask where a path is mounted and how. The `vault` and `bao` CLIs'
// `kv` commands first call sys/internal/ui/mounts/<path> to learn the KV
// version, and fall back to KV version 1 (then fail on every KV v2 path) when
// the answer is a 404. These answers describe the fixed mounts so those
// clients work unchanged.
type mountInfo struct {
	Type                  string            `json:"type"`
	Description           string            `json:"description"`
	Accessor              string            `json:"accessor"`
	Options               map[string]string `json:"options"`
	Config                map[string]any    `json:"config"`
	Local                 bool              `json:"local"`
	SealWrap              bool              `json:"seal_wrap"`
	ExternalEntropyAccess bool              `json:"external_entropy_access"`
}

// fixedMount is a mount and the path it lives at ("secret/").
type fixedMount struct {
	path string
	info mountInfo
}

func newMount(path, typ, description string, options map[string]string) fixedMount {
	return fixedMount{path: path, info: mountInfo{
		Type:        typ,
		Description: description,
		Accessor:    typ + "_" + strings.TrimSuffix(path, "/"),
		Options:     options,
		Config:      map[string]any{"default_lease_ttl": 0, "max_lease_ttl": 0, "force_no_cache": false},
	}}
}

// fixedMounts are the engines uBixVault serves, at the paths it serves them.
var fixedMounts = []fixedMount{
	newMount("secret/", "kv", "key/value secret storage", map[string]string{"version": "2"}),
	newMount("cubbyhole/", "cubbyhole", "per-token private secret storage", nil),
	newMount("transit/", "transit", "encryption as a service", nil),
	newMount("database/", "database", "dynamic database credentials", nil),
	newMount("pki/", "pki", "certificate authority", nil),
	newMount("identity/", "identity", "identity store", nil),
}

// mountFor returns the mount that holds path: the mount path itself, with or
// without its trailing slash, or anything under it.
func mountFor(path string) (fixedMount, bool) {
	for _, m := range fixedMounts {
		if path == strings.TrimSuffix(m.path, "/") || strings.HasPrefix(path, m.path) {
			return m, true
		}
	}
	return fixedMount{}, false
}

// sysMounts answers GET /v1/sys/mounts: every fixed mount, keyed by path. It sits
// behind authenticate, so the token needs read on sys/mounts, as in Vault.
func (h *Handler) sysMounts(w http.ResponseWriter, _ *http.Request) {
	out := make(map[string]mountInfo, len(fixedMounts))
	for _, m := range fixedMounts {
		out[m.path] = m.info
	}
	writeData(w, out)
}

// uiMountForPath answers GET /v1/sys/internal/ui/mounts/<path>: which mount path
// is in and how that mount is configured, in Vault's shape (the mount fields
// plus "path"). As in Vault, any token that can do something in the mount may
// ask, so it does not go through authenticate's check on the request path
// itself: a token that can only read secret/data/app/* must still get an answer
// for secret/app/x, or its `kv get` would fail.
func (h *Handler) uiMountForPath(w http.ResponseWriter, r *http.Request) {
	id := r.Header.Get(tokenHeader)
	if id == "" {
		writeError(w, http.StatusUnauthorized, "missing authentication token")
		return
	}
	tok, err := h.tokens.Lookup(r.Context(), id)
	switch {
	case errors.Is(err, barrier.ErrSealed):
		writeError(w, http.StatusServiceUnavailable, "vault is sealed")
		return
	case errors.Is(err, token.ErrTokenNotFound), errors.Is(err, token.ErrTokenExpired):
		writeError(w, http.StatusForbidden, "permission denied")
		return
	case err != nil:
		writeInternal(w, err)
		return
	}

	m, ok := mountFor(cleanRequestPath(r.PathValue("path")))
	if !ok {
		writeError(w, http.StatusNotFound, "no secrets engine is mounted at this path")
		return
	}
	if !tok.IsRoot() && m.path != "cubbyhole/" { // every token has its own cubbyhole
		acl, err := h.aclFor(r.Context(), tok)
		if err != nil {
			writeInternal(w, err)
			return
		}
		if !acl.HasAccessUnder(m.path) {
			writeError(w, http.StatusForbidden, "permission denied")
			return
		}
	}

	writeData(w, map[string]any{
		"path":                    m.path,
		"type":                    m.info.Type,
		"description":             m.info.Description,
		"accessor":                m.info.Accessor,
		"options":                 m.info.Options,
		"config":                  m.info.Config,
		"local":                   m.info.Local,
		"seal_wrap":               m.info.SealWrap,
		"external_entropy_access": m.info.ExternalEntropyAccess,
	})
}
