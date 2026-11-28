package api

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/cwolsen7905/ubixvault/internal/barrier"
	"github.com/cwolsen7905/ubixvault/internal/ldapauth"
)

// uiMount is one entry of sys/internal/ui/mounts, in Vault's shape.
type uiMount struct {
	Type        string `json:"type"`
	Description string `json:"description"`
}

// uiMountsTTL bounds how often an unauthenticated caller can make the vault
// re-read the userpass user list and the LDAP config. The route is also under
// the global rate limit and audited, like login.
const uiMountsTTL = 10 * time.Second

// uiMountsCache holds the last answer for uiMountsTTL.
type uiMountsCache struct {
	mu   sync.Mutex
	at   time.Time
	auth map[string]uiMount
}

// uiMounts answers GET /v1/sys/internal/ui/mounts without a token, as Vault
// does for its UI's sign-in form. It lists only the sign-in methods a person
// can use from the console and that are set up: token always, userpass once
// it has a user, and LDAP once it has a config. Machine methods (AppRole,
// Kubernetes, JWT, cert) are never listed, and no secrets engine is listed
// without a token. What it reveals is whether userpass has users and whether
// LDAP is configured, nothing about who. A new user or config shows up within
// uiMountsTTL.
func (h *Handler) uiMounts(w http.ResponseWriter, r *http.Request) {
	if h.core.Barrier().Sealed() {
		writeError(w, http.StatusServiceUnavailable, "vault is sealed")
		return
	}
	c := &h.signInCache
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.auth == nil || time.Since(c.at) > uiMountsTTL {
		auth, err := h.signInMethods(r.Context())
		if err != nil {
			writeUIMountsError(w, err)
			return
		}
		c.auth, c.at = auth, time.Now()
	}
	writeData(w, map[string]any{"auth": c.auth, "secret": map[string]uiMount{}})
}

// signInMethods reads which console sign-in methods are set up.
func (h *Handler) signInMethods(ctx context.Context) (map[string]uiMount, error) {
	auth := map[string]uiMount{
		"token/": {Type: "token", Description: "token based credentials"},
	}
	users, err := h.userpass.ListUsers(ctx)
	if err != nil {
		return nil, err
	}
	if len(users) > 0 {
		auth["userpass/"] = uiMount{Type: "userpass", Description: "username and password"}
	}
	switch _, err := h.ldap.ReadConfig(ctx); {
	case err == nil:
		auth["ldap/"] = uiMount{Type: "ldap", Description: "LDAP / Active Directory"}
	case errors.Is(err, ldapauth.ErrNotConfigured):
	default:
		return nil, err
	}
	return auth, nil
}

func writeUIMountsError(w http.ResponseWriter, err error) {
	if errors.Is(err, barrier.ErrSealed) {
		writeError(w, http.StatusServiceUnavailable, "vault is sealed")
		return
	}
	writeInternal(w, err)
}
