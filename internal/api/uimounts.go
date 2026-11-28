package api

import (
	"errors"
	"net/http"

	"github.com/cwolsen7905/ubixvault/internal/barrier"
	"github.com/cwolsen7905/ubixvault/internal/ldapauth"
)

// uiMount is one entry of sys/internal/ui/mounts, in Vault's shape.
type uiMount struct {
	Type        string `json:"type"`
	Description string `json:"description"`
}

// uiMounts answers GET /v1/sys/internal/ui/mounts without a token, as Vault
// does for its UI's sign-in form. It lists only the sign-in methods a person
// can use from the console and that are set up: token always, userpass once
// it has a user, and LDAP once it has a config. Machine methods (AppRole,
// Kubernetes, JWT, cert) are never listed, and no secrets engine is listed
// without a token. What it reveals is whether userpass has users and whether
// LDAP is configured, nothing about who.
func (h *Handler) uiMounts(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	auth := map[string]uiMount{
		"token/": {Type: "token", Description: "token based credentials"},
	}

	users, err := h.userpass.ListUsers(ctx)
	if err != nil {
		writeUIMountsError(w, err)
		return
	}
	if len(users) > 0 {
		auth["userpass/"] = uiMount{Type: "userpass", Description: "username and password"}
	}

	switch _, err := h.ldap.ReadConfig(ctx); {
	case err == nil:
		auth["ldap/"] = uiMount{Type: "ldap", Description: "LDAP / Active Directory"}
	case errors.Is(err, ldapauth.ErrNotConfigured):
	default:
		writeUIMountsError(w, err)
		return
	}

	writeData(w, map[string]any{"auth": auth, "secret": map[string]uiMount{}})
}

func writeUIMountsError(w http.ResponseWriter, err error) {
	if errors.Is(err, barrier.ErrSealed) {
		writeError(w, http.StatusServiceUnavailable, "vault is sealed")
		return
	}
	writeInternal(w, err)
}
