// Package policy implements ACL policies (docs/DESIGN.md §3.5): named sets of
// path rules that grant capabilities on API paths. Access is default-deny, and
// an explicit deny overrides any grant.
//
// Policies are expressed as JSON (a format HashiCorp Vault also accepts):
//
//	{
//	  "path": {
//	    "secret/data/app/*": { "capabilities": ["read", "list"] },
//	    "secret/data/admin/*": { "capabilities": ["deny"] }
//	  }
//	}
//
// HCL parity is a follow-up; the semantics are identical.
package policy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/cwolsen7905/ubixvault/internal/storage"
)

// Capability is an action a policy may grant on a path.
type Capability string

// The capabilities a policy rule may grant.
const (
	Create Capability = "create"
	Read   Capability = "read"
	Update Capability = "update"
	Delete Capability = "delete"
	List   Capability = "list"
	Sudo   Capability = "sudo"
	Deny   Capability = "deny" // explicit deny; overrides any grant
)

var validCapabilities = map[Capability]bool{
	Create: true, Read: true, Update: true, Delete: true, List: true, Sudo: true, Deny: true,
}

// storePrefix is the storage namespace for policy documents.
const storePrefix = "sys/policy/"

// Errors.
var (
	ErrPolicyNotFound = errors.New("policy: not found")
	ErrInvalidName    = errors.New("policy: invalid name")
	// ErrReservedName is returned when writing a policy named "root". That name
	// means unrestricted access on a token; an ACL policy using it would only
	// mislead. Vault refuses it too.
	ErrReservedName      = errors.New("policy: the name \"root\" is reserved")
	ErrUnknownCapability = errors.New("policy: unknown capability")
	ErrMalformedPolicy   = errors.New("policy: malformed document")
)

// Rule grants a set of capabilities on a path pattern. A pattern ending in "*"
// matches by prefix; otherwise it matches exactly.
//
// AllowedParameters, DeniedParameters and RequiredParameters limit the request
// body parameters of a write, with Vault's semantics (see [Parameters.Allows]). Keys are kept as
// written so the policy reads back unchanged; matching ignores their case.
type Rule struct {
	Path               string
	Capabilities       []Capability
	AllowedParameters  map[string][]any
	DeniedParameters   map[string][]any
	RequiredParameters []string
}

// Policy is a named collection of rules.
type Policy struct {
	Name  string
	Rules []Rule
}

// document is the JSON wire form.
type document struct {
	Path map[string]pathEntry `json:"path"`
}

type pathEntry struct {
	Capabilities       []Capability     `json:"capabilities"`
	AllowedParameters  map[string][]any `json:"allowed_parameters,omitempty"`
	DeniedParameters   map[string][]any `json:"denied_parameters,omitempty"`
	RequiredParameters []string         `json:"required_parameters,omitempty"`
}

// ParseDocument builds a policy from either a JSON or an HCL document, detecting
// the format: content whose first non-space byte is '{' is treated as JSON,
// otherwise as HCL.
func ParseDocument(name string, data []byte) (*Policy, error) {
	trimmed := bytesTrimLeadingSpace(data)
	if len(trimmed) > 0 && trimmed[0] == '{' {
		return Parse(name, data)
	}
	return ParseHCL(name, data)
}

func bytesTrimLeadingSpace(data []byte) []byte {
	i := 0
	for i < len(data) && (data[i] == ' ' || data[i] == '\t' || data[i] == '\n' || data[i] == '\r') {
		i++
	}
	return data[i:]
}

// Parse builds a named policy from its JSON document. Unknown keys are an
// error, at the top level and per path: silently dropping one would store a
// different policy than the operator wrote — a misspelled "path" becomes an
// empty policy, and a dropped restriction (such as Vault's
// min_wrapping_ttl, which uBixVault does not implement) would grant more than
// intended.
func Parse(name string, data []byte) (*Policy, error) {
	var doc document
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformedPolicy, err)
	}
	p := &Policy{Name: name}
	for path, entry := range doc.Path {
		for _, c := range entry.Capabilities {
			if !validCapabilities[c] {
				return nil, fmt.Errorf("%w: %q", ErrUnknownCapability, c)
			}
		}
		if err := validateParameters("allowed_parameters", entry.AllowedParameters); err != nil {
			return nil, err
		}
		if err := validateParameters("denied_parameters", entry.DeniedParameters); err != nil {
			return nil, err
		}
		if err := validateRequired(entry.RequiredParameters); err != nil {
			return nil, err
		}
		p.Rules = append(p.Rules, Rule{
			Path:               path,
			Capabilities:       entry.Capabilities,
			AllowedParameters:  entry.AllowedParameters,
			DeniedParameters:   entry.DeniedParameters,
			RequiredParameters: entry.RequiredParameters,
		})
	}
	sort.Slice(p.Rules, func(i, j int) bool { return p.Rules[i].Path < p.Rules[j].Path })
	return p, nil
}

// Document renders the policy back to its JSON form for storage.
func (p *Policy) Document() ([]byte, error) {
	doc := document{Path: map[string]pathEntry{}}
	for _, r := range p.Rules {
		doc.Path[r.Path] = pathEntry{
			Capabilities:       r.Capabilities,
			AllowedParameters:  r.AllowedParameters,
			DeniedParameters:   r.DeniedParameters,
			RequiredParameters: r.RequiredParameters,
		}
	}
	return json.Marshal(doc)
}

// Templated returns a copy of the policy with {{...}} placeholders in rule paths
// resolved via resolve (e.g. "identity.entity.id" -> the entity's ID). A rule
// whose placeholders do not all resolve is dropped, so a templated grant is
// worthless to a caller lacking the value (fail-closed). A policy with no
// placeholders is returned unchanged — the common case, at no cost.
func (p *Policy) Templated(resolve func(key string) (string, bool)) *Policy {
	hasTemplate := false
	for _, r := range p.Rules {
		if containsTemplate(r.Path) {
			hasTemplate = true
			break
		}
	}
	if !hasTemplate {
		return p
	}
	out := &Policy{Name: p.Name}
	for _, r := range p.Rules {
		if !containsTemplate(r.Path) {
			out.Rules = append(out.Rules, r)
			continue
		}
		expanded, ok := expandTemplate(r.Path, resolve)
		if !ok {
			continue // unresolved placeholder — drop the rule
		}
		r.Path = expanded // keep the rest of the rule, parameter limits included
		out.Rules = append(out.Rules, r)
	}
	return out
}

func containsTemplate(s string) bool { return strings.Contains(s, "{{") }

// expandTemplate replaces each {{ key }} placeholder in s with resolve(key). If
// any placeholder is unresolved, ok is false. An unterminated "{{" is left
// literal.
func expandTemplate(s string, resolve func(key string) (string, bool)) (string, bool) {
	var b strings.Builder
	for {
		i := strings.Index(s, "{{")
		if i < 0 {
			b.WriteString(s)
			return b.String(), true
		}
		rest := s[i+2:]
		j := strings.Index(rest, "}}")
		if j < 0 {
			b.WriteString(s) // no closing braces; leave the remainder literal
			return b.String(), true
		}
		b.WriteString(s[:i])
		key := strings.TrimSpace(rest[:j])
		val, ok := resolve(key)
		if !ok {
			return "", false
		}
		b.WriteString(val)
		s = rest[j+2:]
	}
}

// ACL is the merged rule set from one or more policies attached to a token.
type ACL struct {
	rules []Rule
}

// NewACL merges the given policies into an evaluatable ACL.
func NewACL(policies ...*Policy) *ACL {
	a := &ACL{}
	for _, p := range policies {
		a.rules = append(a.rules, p.Rules...)
	}
	return a
}

// Allows reports whether the ACL grants the capability on path. Evaluation is
// default-deny; an explicit deny on any matching rule wins over every grant.
func (a *ACL) Allows(path string, capability Capability) bool {
	allowed := false
	for _, r := range a.rules {
		if !matchPath(r.Path, path) {
			continue
		}
		if hasCapability(r.Capabilities, Deny) {
			return false
		}
		if hasCapability(r.Capabilities, capability) {
			allowed = true
		}
	}
	return allowed
}

// Capabilities lists what the ACL grants on path, sorted, the way Vault's
// sys/capabilities-self reports it: ["deny"] when a matching rule denies or
// nothing is granted. Parameter limits are not reflected (as in Vault).
func (a *ACL) Capabilities(path string) []string {
	granted := map[Capability]bool{}
	for _, r := range a.rules {
		if !matchPath(r.Path, path) {
			continue
		}
		if hasCapability(r.Capabilities, Deny) {
			return []string{string(Deny)}
		}
		for _, c := range r.Capabilities {
			granted[c] = true
		}
	}
	if len(granted) == 0 {
		return []string{string(Deny)}
	}
	out := make([]string, 0, len(granted))
	for c := range granted {
		out = append(out, string(c))
	}
	sort.Strings(out)
	return out
}

// HasAccessUnder reports whether the ACL grants any capability other than deny
// on some path under prefix (a mount path such as "secret/"). It is Vault's
// "has mount access" check, used by sys/internal/ui/mounts/<path>: a token may
// learn which mount a path is in, and how it is configured, if it can do
// anything at all in that mount. A rule counts if its path is under prefix, or if
// it is a glob whose stem covers prefix ("secret/*", "*").
func (a *ACL) HasAccessUnder(prefix string) bool {
	for _, r := range a.rules {
		stem := strings.TrimSuffix(r.Path, "*")
		glob := stem != r.Path
		under := strings.HasPrefix(r.Path, prefix) || (glob && strings.HasPrefix(prefix, stem))
		if !under {
			continue
		}
		for _, c := range r.Capabilities {
			if c != Deny {
				return true
			}
		}
	}
	return false
}

func matchPath(pattern, path string) bool {
	if strings.HasSuffix(pattern, "*") {
		return strings.HasPrefix(path, strings.TrimSuffix(pattern, "*"))
	}
	return pattern == path
}

func hasCapability(caps []Capability, want Capability) bool {
	for _, c := range caps {
		if c == want {
			return true
		}
	}
	return false
}

// Storage is the subset of a backend the policy store needs.
type Storage interface {
	Get(ctx context.Context, key string) (*storage.Entry, error)
	Put(ctx context.Context, entry *storage.Entry) error
	Delete(ctx context.Context, key string) error
	List(ctx context.Context, prefix string) ([]string, error)
}

// Store persists and retrieves policies.
type Store struct {
	store Storage
}

// NewStore returns a policy store over s.
func NewStore(s Storage) *Store { return &Store{store: s} }

// Set creates or replaces a policy.
func (s *Store) Set(ctx context.Context, p *Policy) error {
	if !validName(p.Name) {
		return ErrInvalidName
	}
	if strings.EqualFold(strings.TrimSpace(p.Name), "root") {
		return ErrReservedName
	}
	doc, err := p.Document()
	if err != nil {
		return fmt.Errorf("policy: render: %w", err)
	}
	if err := s.store.Put(ctx, &storage.Entry{Key: storePrefix + p.Name, Value: doc}); err != nil {
		return fmt.Errorf("policy: persist: %w", err)
	}
	return nil
}

// Get returns the named policy, or [ErrPolicyNotFound].
func (s *Store) Get(ctx context.Context, name string) (*Policy, error) {
	if !validName(name) {
		return nil, ErrInvalidName
	}
	entry, err := s.store.Get(ctx, storePrefix+name)
	if err != nil {
		return nil, fmt.Errorf("policy: read: %w", err)
	}
	if entry == nil {
		return nil, ErrPolicyNotFound
	}
	return Parse(name, entry.Value)
}

// Delete removes the named policy. It is a no-op if absent.
func (s *Store) Delete(ctx context.Context, name string) error {
	if !validName(name) {
		return ErrInvalidName
	}
	if err := s.store.Delete(ctx, storePrefix+name); err != nil {
		return fmt.Errorf("policy: delete: %w", err)
	}
	return nil
}

// List returns the names of all stored policies.
func (s *Store) List(ctx context.Context) ([]string, error) {
	names, err := s.store.List(ctx, storePrefix)
	if err != nil {
		return nil, fmt.Errorf("policy: list: %w", err)
	}
	return names, nil
}

// validName restricts policy names to a single, path-safe segment.
func validName(name string) bool {
	if name == "" || strings.Contains(name, "/") {
		return false
	}
	return storage.ValidateKey(storePrefix+name) == nil
}
