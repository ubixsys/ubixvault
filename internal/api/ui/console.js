"use strict";
// uBixVault console. Vanilla JS, no dependencies, no build step. Secret values
// are rendered via textContent only (never innerHTML), so a value can't inject
// markup.
//
// Layout: an app shell (sidebar, top bar, pages) driven by a hash router
// (#/, #/kv/<path>, #/policies[/<name>], #/tokens, #/pki). While the vault is
// uninitialized or sealed only the lifecycle page shows; while signed out only
// the sign-in page shows.

const $ = (id) => document.getElementById(id);
const TOKEN_KEY = "ubixvault.token";
// How the current token was obtained: "userpass" / "ldap" when this console
// logged in (so signing out revokes it), "token" when it was pasted in (so
// signing out only forgets it — a pasted token may be root or shared).
const SOURCE_KEY = "ubixvault.token-source";
const USER_KEY = "ubixvault.token-user";
const THEME_KEY = "ubixvault.theme";

const getToken = () => sessionStorage.getItem(TOKEN_KEY) || "";
function setToken(t, source, user) {
  if (t) {
    sessionStorage.setItem(TOKEN_KEY, t);
    sessionStorage.setItem(SOURCE_KEY, source || "token");
    if (user) sessionStorage.setItem(USER_KEY, user);
    else sessionStorage.removeItem(USER_KEY);
  } else {
    for (const k of [TOKEN_KEY, SOURCE_KEY, USER_KEY]) sessionStorage.removeItem(k);
  }
}

// api performs a same-origin request, attaching the token and JSON body if given.
async function api(method, path, body) {
  const headers = {};
  const tok = getToken();
  if (tok) headers["X-Vault-Token"] = tok;
  const opts = { method, headers };
  if (body !== undefined) {
    headers["Content-Type"] = "application/json";
    opts.body = JSON.stringify(body);
  }
  let res;
  try { res = await fetch(path, opts); } catch (_) { return { status: 0, ok: false, body: null }; }
  let payload = null;
  try { payload = await res.json(); } catch (_) { /* 204 / empty */ }
  return { status: res.status, ok: res.ok, body: payload };
}

// apiRaw sends a raw (non-JSON-wrapped) body — policy documents are posted verbatim.
async function apiRaw(method, path, text) {
  const headers = {};
  const tok = getToken();
  if (tok) headers["X-Vault-Token"] = tok;
  let res;
  try { res = await fetch(path, { method, headers, body: text }); } catch (_) { return { status: 0, ok: false, body: null }; }
  let payload = null;
  try { payload = await res.json(); } catch (_) { /* 204 / empty */ }
  return { status: res.status, ok: res.ok, body: payload };
}

function friendlyError(status, body) {
  const detail = body && body.errors && body.errors.length ? " — " + body.errors.join("; ") : "";
  switch (status) {
    case 0: return "Can't reach the vault.";
    case 401:
    case 403: return "Not authorized — check your token." + detail;
    case 404: return "Not found." + detail;
    case 501: return "Vault is not initialized.";
    case 503: return "Vault is sealed." + detail;
    default: return "Request failed (" + status + ")" + detail;
  }
}

// ---- small DOM helpers ----
function el(tag, cls, text) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text != null) e.textContent = text;
  return e;
}

function actionButton(label, cls, onClick) {
  const b = el("button", cls, label);
  b.type = "button";
  if (onClick) b.addEventListener("click", onClick);
  return b;
}

function link(label, href, cls) {
  const a = el("a", cls, label);
  a.href = href;
  return a;
}

function panelMsg(id, cls, text) {
  const out = $(id);
  out.replaceChildren();
  out.appendChild(el("div", "msg " + cls, text));
}

// pageState fills out with one of the shared page states: loading, empty,
// error or denied. A 403 is shown as denied, naming the path.
function pageState(out, kind, text, actions) {
  out.replaceChildren();
  const s = el("div", "state " + kind, text);
  if (actions && actions.length) {
    const a = el("div", "state-actions kv-actions");
    a.append(...actions);
    s.appendChild(a);
  }
  out.appendChild(s);
  return s;
}

function errorState(out, r, path) {
  if (r.status === 403) {
    return pageState(out, "denied", "Your token is not allowed to do this" + (path ? " on " + path : "") + ".");
  }
  return pageState(out, "error", friendlyError(r.status, r.body));
}

function kvRows(table, rows) {
  table.replaceChildren();
  for (const [k, v] of rows) {
    const tr = el("tr");
    tr.append(el("th", null, k), el("td", null, v));
    table.appendChild(tr);
  }
}

let toastTimer = 0;
function toast(text, cls) {
  const t = $("toast");
  t.textContent = text;
  t.className = "toast" + (cls ? " " + cls : "");
  t.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { t.hidden = true; }, 3500);
}

function copy(text, what) {
  if (!navigator.clipboard) { toast("Copying needs a secure context (HTTPS).", "error"); return; }
  navigator.clipboard.writeText(text).then(
    () => toast((what || "Value") + " copied."),
    () => toast("Could not copy.", "error"));
}

// confirmThen swaps btn for an inline confirmation naming the target. With
// typed set, the user must type that word before Yes does anything.
function confirmThen(btn, question, onYes, typed) {
  const holder = el("span", "confirm");
  holder.appendChild(el("span", "q", question));
  let input = null;
  if (typed) {
    input = el("input");
    input.type = "text";
    input.placeholder = "type " + typed;
    input.setAttribute("aria-label", "type " + typed + " to confirm");
    holder.appendChild(input);
  }
  const yes = actionButton("Yes", "btn-danger small", () => {
    if (input && input.value.trim() !== typed) { input.focus(); return; }
    onYes();
  });
  const no = actionButton("No", "ghost small", () => holder.replaceWith(btn));
  holder.append(yes, no);
  btn.replaceWith(holder);
  (input || yes).focus();
}

function fmtUptime(s) {
  s = Math.floor(s || 0);
  const d = Math.floor(s / 86400), h = Math.floor((s % 86400) / 3600),
    m = Math.floor((s % 3600) / 60), sec = s % 60;
  if (d) return `${d}d ${h}h`;
  if (h) return `${h}h ${m}m`;
  if (m) return `${m}m ${sec}s`;
  return `${sec}s`;
}

function fmtDuration(s) {
  s = Math.max(0, Math.floor(s || 0));
  const d = Math.floor(s / 86400), h = Math.floor((s % 86400) / 3600), m = Math.floor((s % 3600) / 60);
  if (d) return `${d}d ${h}h`;
  if (h) return `${h}h ${m}m`;
  if (m) return `${m}m`;
  return `${s}s`;
}

// ---- theme ----
// The theme is "system" (follow the OS, the default), "light" or "dark". The
// button cycles through the three; the choice is kept per browser.
const THEMES = ["system", "light", "dark"];

function storedTheme() {
  let t = "";
  try { t = localStorage.getItem(THEME_KEY) || ""; } catch (_) { /* storage blocked */ }
  return THEMES.includes(t) ? t : "system";
}

function effectiveTheme() {
  const t = document.documentElement.dataset.theme;
  if (t === "light" || t === "dark") return t;
  return window.matchMedia && window.matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark";
}

let theme = "system";

function applyTheme(t) {
  theme = THEMES.includes(t) ? t : "system";
  if (theme === "system") delete document.documentElement.dataset.theme;
  else document.documentElement.dataset.theme = theme;
  const label = { system: "System", light: "Light", dark: "Dark" }[theme];
  const next = THEMES[(THEMES.indexOf(theme) + 1) % THEMES.length];
  const b = $("theme-toggle");
  b.textContent = "Theme: " + label;
  b.title = theme === "system" ? "Following the system (" + effectiveTheme() + ")" : label + " theme";
  b.setAttribute("aria-label", "Theme: " + label + ". Switch to " + next + ".");
}

function toggleTheme() {
  const next = THEMES[(THEMES.indexOf(theme) + 1) % THEMES.length];
  try {
    if (next === "system") localStorage.removeItem(THEME_KEY);
    else localStorage.setItem(THEME_KEY, next);
  } catch (_) { /* per-tab only */ }
  applyTheme(next);
}

// ---- vault and session state ----
const vault = { reachable: false, initialized: false, sealed: true, type: "", version: "", uptime: null, standby: false };
let session = null; // token lookup data while signed in
// While freshly generated keys are on screen, the lifecycle page stays up even
// though the vault is now initialized: hiding it would hide the keys with it.
let showingInitSecrets = false;

function mode() {
  if (!vault.reachable || !vault.initialized || vault.sealed || showingInitSecrets) return "lifecycle";
  if (!session) return "signin";
  return "shell";
}

async function refreshStatus() {
  const hero = $("seal");
  const [health, seal] = await Promise.all([
    api("GET", "/v1/sys/health"),
    api("GET", "/v1/sys/seal-status"),
  ]);
  // Only a real seal-status answer counts: a proxy error or a 5xx with a JSON
  // body must not read as "uninitialized" and eject a signed-in user.
  if (!seal.ok || !seal.body || typeof seal.body.initialized !== "boolean") {
    vault.reachable = false;
    hero.dataset.state = "error";
    $("seal-word").textContent = "Unreachable";
    $("seal-tagline").textContent = "Could not reach the vault";
    setBadge("error", "Unreachable");
    return;
  }
  const st = seal.body;
  const h = health.body || {};
  Object.assign(vault, {
    reachable: true, initialized: !!st.initialized, sealed: !!st.sealed, type: st.type || "",
    version: h.version || "", uptime: h.uptime_seconds, standby: !!h.standby,
  });
  $("version").textContent = vault.version ? "v" + vault.version : "";
  $("m-init").textContent = st.initialized ? "yes" : "no";
  $("m-type").textContent = st.type || "—";
  $("m-uptime").textContent = h.uptime_seconds != null ? fmtUptime(h.uptime_seconds) : "—";

  let state, word, tag;
  if (!st.initialized) {
    state = "uninitialized"; word = "Uninitialized"; tag = "Run operator init to set up the vault";
  } else if (st.sealed) {
    state = "sealed"; word = "Sealed"; tag = "The vault is locked; unseal to serve secrets";
  } else {
    state = "unsealed"; word = "Unsealed"; tag = "The vault is unlocked and serving";
  }
  hero.dataset.state = state;
  $("seal-word").textContent = word;
  $("seal-tagline").textContent = tag;
  setBadge(state, word + (vault.standby ? " · standby" : ""));
  reflectLifecycle(st);
}

function setBadge(state, text) {
  $("seal-badge").dataset.state = state;
  $("seal-badge-text").textContent = text;
}

function reflectLifecycle(st) {
  $("init-panel").hidden = !(!st.initialized || showingInitSecrets);
  const sealed = !!st.initialized && !!st.sealed;
  $("unseal-panel").hidden = !sealed;
  if (!sealed) return;

  const auto = st.type === "auto";
  $("unseal-form").hidden = auto;
  $("unseal-hint").textContent = auto
    ? "This vault unseals itself with its seal (auto-unseal). If it stays sealed, the seal " +
      "(KMS or key) is unreachable — check the server log; key shares cannot unseal it."
    : "Enter key shares one at a time; the vault unseals when enough have been given. " +
      "A share is sent only to this vault and is not kept in the browser.";
  const tag = $("unseal-progress");
  tag.textContent = (st.progress || 0) + " of " + (st.t || "?");
  tag.dataset.set = String((st.progress || 0) > 0);
}

// ---- lifecycle: initialize and unseal ----
// secretList renders labelled values, each with a Copy button, into out.
function secretList(out, title, values) {
  const head = el("h3", "sub", title);
  const list = el("div", "keys");
  values.forEach((v, i) => {
    const row = el("div", "keyrow");
    const code = el("code", null, v);
    row.append(el("span", "n", values.length > 1 ? String(i + 1) : ""), code,
      actionButton("Copy", "ghost small", () => copy(v, "Value")));
    list.appendChild(row);
  });
  out.append(head, list);
}

async function initVault() {
  const shares = parseInt($("init-shares").value, 10);
  const threshold = parseInt($("init-threshold").value, 10);
  if (!(shares >= 2 && shares <= 255 && threshold >= 2 && threshold <= shares)) {
    panelMsg("init-out", "error", "Use 2–255 shares, and a threshold from 2 up to the number of shares.");
    return;
  }
  const r = await api("POST", "/v1/sys/init", { secret_shares: shares, secret_threshold: threshold });
  if (!r.ok) { panelMsg("init-out", "error", friendlyError(r.status, r.body)); return; }
  const b = r.body || {};
  const keys = (b.recovery_keys && b.recovery_keys.length) ? b.recovery_keys : (b.keys || []);
  const recovery = !!(b.recovery_keys && b.recovery_keys.length);

  showingInitSecrets = true;
  $("init-form").hidden = true;
  const out = $("init-out"); out.replaceChildren();
  out.appendChild(el("div", "warn", "Shown once. Copy every " + (recovery ? "recovery key" : "key share") +
    " and the root token somewhere safe and offline now — they cannot be shown again."));
  secretList(out, (recovery ? "Recovery keys" : "Key shares") + " — any " + threshold + " of " + keys.length +
    (recovery ? " regenerate a root token" : " unseal the vault"), keys);
  secretList(out, "Root token", [b.root_token || ""]);
  const acts = el("div", "kv-actions");
  acts.appendChild(actionButton("Use root token in this tab", "", async () => {
    setToken(b.root_token || "", "token");
    await refreshSession();
  }));
  acts.appendChild(actionButton("I've stored them — hide", "ghost", async () => {
    showingInitSecrets = false;
    out.replaceChildren();
    $("init-form").hidden = false;
    await refreshStatus();
    await refreshSession();
    render();
  }));
  out.appendChild(acts);
  await refreshStatus();
}

async function submitUnsealShare() {
  const key = $("unseal-key").value.trim();
  $("unseal-key").value = ""; // never keep a share in the page
  if (!key) { panelMsg("unseal-out", "error", "Enter a key share."); return; }
  const r = await api("POST", "/v1/sys/unseal", { key });
  if (!r.ok) { panelMsg("unseal-out", "error", friendlyError(r.status, r.body)); return; }
  const st = r.body || {};
  if (st.sealed === false) {
    panelMsg("unseal-out", "ok", "Unsealed.");
    await refreshStatus();
    await refreshSession();
    render();
    return;
  }
  panelMsg("unseal-out", "ok", "Share accepted — " + (st.progress || 0) + " of " + (st.t || "?") + ".");
  await refreshStatus();
}

// ---- session: sign in, who am I, renew, sign out ----
const LOGIN_METHODS = { userpass: "Username & password", ldap: "LDAP", token: "Token" };

// The sign-in methods to offer: those the vault says are set up (Vault's
// sys/internal/ui/mounts, no token needed). If the vault cannot say, all three
// stay, so sign-in never becomes impossible.
const METHOD_ORDER = ["userpass", "ldap", "token"];

async function loadLoginMethods() {
  const r = await api("GET", "/v1/sys/internal/ui/mounts");
  const auth = r.ok && r.body && r.body.data && r.body.data.auth;
  if (!auth) return;
  const available = METHOD_ORDER.filter((m) => auth[m + "/"]);
  if (!available.length) return;
  const sel = $("login-method");
  const was = sel.value;
  sel.replaceChildren();
  for (const m of available) {
    const o = el("option", null, LOGIN_METHODS[m]);
    o.value = m;
    sel.appendChild(o);
  }
  sel.value = available.includes(was) ? was : available[0];
  // With a single method there is nothing to choose.
  $("login-method").hidden = available.length === 1;
  $("login-method-label").hidden = available.length === 1;
  reflectLoginMethod();
}

function reflectLoginMethod() {
  const tokenMode = $("login-method").value === "token";
  for (const id of ["login-user", "login-user-label", "login-pass", "login-pass-label"]) $(id).hidden = tokenMode;
  for (const id of ["login-token", "login-token-label"]) $(id).hidden = !tokenMode;
}

function signedOutMessage(message, cls) {
  if (message) panelMsg("session-out", cls || "ok", message);
  else $("session-out").replaceChildren();
}

// refreshSession looks up the stored token and records who it is, or clears
// the session when there is none (or it has expired or been revoked).
async function refreshSession() {
  if (!getToken()) { session = null; return; }
  const r = await api("GET", "/v1/auth/token/lookup-self");
  if (r.status === 403) {
    setToken("");
    session = null;
    signedOutMessage("Your session has expired or was revoked. Sign in again.", "error");
    return;
  }
  if (!r.ok) {
    // Sealed: the lifecycle page shows why. Anything else (a 500, a dropped
    // connection): keep the token, and say why the sign-in form is showing.
    if (r.status !== 503) {
      signedOutMessage("Could not check your saved session: " + friendlyError(r.status, r.body) +
        " Reload to try again, or sign in.", "error");
    }
    return;
  }
  session = (r.body && r.body.data) || {};
  const source = sessionStorage.getItem(SOURCE_KEY) || "token";
  const user = sessionStorage.getItem(USER_KEY);
  const d = session;
  const rows = [
    ["signed in", (LOGIN_METHODS[source] || source) + (user ? " · " + user : "")],
    ["policies", (d.policies || []).join(", ") || "(none)"],
  ];
  if ((d.identity_policies || []).length) rows.push(["identity policies", d.identity_policies.join(", ")]);
  rows.push(["expires", d.expire_time ? "in " + fmtDuration(d.ttl) + " (" + d.expire_time + ")" : "never"]);
  kvRows($("whoami-table"), rows);
  $("renew").hidden = !d.renewable;
  // Pasted tokens are only forgotten, never revoked — say so on the buttons.
  const label = source === "token" ? "Forget token" : "Sign out";
  $("logout").textContent = label;
  $("nav-signout").textContent = label;
  $("nav-user").textContent = (user || (d.display_name || "token")) + " · " +
    ((d.policies || []).join(", ") || "no policies");
  $("session-out").replaceChildren();
}

async function login() {
  const method = $("login-method").value;
  if (method === "token") {
    const tok = $("login-token").value.trim();
    $("login-token").value = "";
    if (!tok) { panelMsg("session-out", "error", "Paste a token."); return; }
    setToken(tok, "token");
    await refreshSession();
    if (!session && getToken()) panelMsg("session-out", "error", "The vault could not look up this token.");
    afterSignIn();
    return;
  }
  const user = $("login-user").value.trim();
  const password = $("login-pass").value;
  $("login-pass").value = ""; // never keep the password around, whatever happens
  if (!user || !password) { panelMsg("session-out", "error", "Enter a username and password."); return; }
  const r = await api("POST", "/v1/auth/" + method + "/login/" + encodeURIComponent(user), { password });
  if (!r.ok) {
    // Login failures are deliberately uniform server-side; keep them uniform here.
    const msg = r.status === 400 || r.status === 401 || r.status === 403
      ? "Sign-in failed — check the username and password."
      : friendlyError(r.status, r.body);
    panelMsg("session-out", "error", msg);
    return;
  }
  const tok = r.body && r.body.auth && r.body.auth.client_token;
  if (!tok) { panelMsg("session-out", "error", "The vault returned no token."); return; }
  setToken(tok, method, user);
  await refreshSession();
  afterSignIn();
}

function afterSignIn() {
  if (!session) { render(); return; }
  if (!location.hash || location.hash === "#") location.hash = "#/";
  render();
}

async function renew() {
  const r = await api("POST", "/v1/auth/token/renew-self", {});
  if (r.status === 403) { toast("Your policies don't allow renewing this token (auth/token/renew-self).", "error"); return; }
  if (!r.ok) { toast(friendlyError(r.status, r.body), "error"); return; }
  await refreshSession();
  toast("Renewed.");
}

async function logout() {
  const source = sessionStorage.getItem(SOURCE_KEY) || "token";
  if (source !== "token") {
    // Revoke the token this console created. If that fails (e.g. sealed), still
    // forget it locally, and say it may remain valid until it expires.
    const r = await api("POST", "/v1/auth/token/revoke-self", {});
    setToken("");
    session = null;
    signedOutMessage(r.ok ? "Signed out; the token was revoked."
      : "Signed out here, but the vault could not revoke the token (" + r.status + "); it stays valid until it expires.",
      r.ok ? "ok" : "error");
  } else {
    setToken("");
    session = null;
    signedOutMessage("Token forgotten in this tab. It was not revoked.");
  }
  render();
}

// ---- router ----
function safeDecode(s) {
  try { return decodeURIComponent(s); } catch (_) { return s; }
}

function parseRoute() {
  const h = location.hash.replace(/^#/, "");
  if (!h || h === "/") return { page: "dashboard" };
  if (!h.startsWith("/")) return { page: "notfound" };
  const [head, ...rest] = h.slice(1).split("/");
  switch (head) {
    case "kv": return { page: "kv", path: rest.map(safeDecode).join("/") };
    case "policies": return { page: "policies", name: safeDecode(rest.join("/")) };
    case "tokens": return { page: "tokens" };
    case "access": return { page: "access", method: rest[0] || "", name: safeDecode(rest.slice(1).join("/")) };
    case "pki": return { page: "pki" };
    default: return { page: "notfound" };
  }
}

const kvHref = (p) => "#/kv/" + p.split("/").map(encodeURIComponent).join("/");
const PAGES = ["lifecycle", "signin", "dashboard", "kv", "access", "policies", "tokens", "pki", "notfound"];
const TITLES = { dashboard: "Dashboard", kv: "Key/value", access: "Access", policies: "Policies", tokens: "Tokens", pki: "PKI", notfound: "Not found" };

function showPage(name) {
  for (const p of PAGES) $("page-" + p).hidden = p !== name;
}

function setCrumbs(items) {
  const nav = $("crumbs");
  nav.replaceChildren();
  items.forEach(([label, href], i) => {
    if (i) nav.appendChild(el("span", "sep", "/"));
    if (i === items.length - 1) {
      const cur = el("span", null, label);
      cur.setAttribute("aria-current", "page");
      nav.appendChild(cur);
    } else {
      nav.appendChild(link(label, href));
    }
  });
}

function markNav(page) {
  for (const a of $("nav").querySelectorAll("a[data-nav]")) {
    if (a.dataset.nav === page) a.setAttribute("aria-current", "page");
    else a.removeAttribute("aria-current");
  }
}

// gen counts renders. A loader notes it before awaiting and drops its result
// if the user has moved on, so a slow response never overwrites another page.
let gen = 0;
const stale = (g) => g !== gen;

// clearPage drops what a page left on screen, so revealed secrets, a token
// shown once or a private key do not stay in the hidden DOM after leaving it.
function clearPage(name) {
  const outs = {
    kv: ["kv-out"], access: ["access-out"], policies: ["pol-out", "cap-out"], tokens: ["tok-out"],
    pki: ["pki-ca-out", "pki-role-out", "pki-issue-out"], dashboard: ["dash-engines"],
  }[name] || [];
  for (const id of outs) $(id).replaceChildren();
  if (name === "kv") closeEditor();
  if (name === "policies") closePolEditor();
  if (name === "access") closeAccessEditor();
}

let lastMode = "";
let lastPage = "";
function render() {
  gen++;
  const m = mode();
  $("app").dataset.mode = m;
  if (m !== "shell" && lastPage) { clearPage(lastPage); lastPage = ""; }
  if (m === "lifecycle") { showPage("lifecycle"); lastMode = m; return; }
  if (m === "signin") {
    showPage("signin");
    if (lastMode !== m) loadLoginMethods().then(() => {
      if (mode() !== "signin") return; // moved on while the request was out
      const first = $("login-method").hidden ? ($("login-token").hidden ? $("login-user") : $("login-token")) : $("login-method");
      first.focus();
    });
    lastMode = m;
    return;
  }
  lastMode = m;
  const route = parseRoute();
  if (lastPage && lastPage !== route.page) clearPage(lastPage);
  lastPage = route.page;
  showPage(route.page);
  markNav(route.page);
  $("app").classList.remove("nav-open");
  $("nav-toggle").setAttribute("aria-expanded", "false");
  document.title = (TITLES[route.page] || "Console") + " — uBixVault";
  switch (route.page) {
    case "dashboard": setCrumbs([["Dashboard", "#/"]]); loadDashboard(); break;
    case "kv": kvRoute(route.path); break;
    case "access": accessRoute(route.method, route.name); break;
    case "policies": polRoute(route.name); break;
    case "tokens": setCrumbs([["Access", "#/tokens"], ["Tokens", "#/tokens"]]); break;
    case "pki": setCrumbs([["Secrets", "#/kv/"], ["PKI", "#/pki"]]); break;
    default: setCrumbs([["Not found", location.hash]]);
  }
}

// ---- dashboard ----
// The engines and auth methods uBixVault serves, each at its one fixed path,
// with the path probed for the signed-in token's capabilities.
const ENGINES = [
  { name: "Key/value (v2)", kind: "secrets", path: "secret/", probe: "secret/metadata/", open: "#/kv/" },
  { name: "Transit", kind: "secrets", path: "transit/", probe: "transit/keys/" },
  { name: "Database", kind: "secrets", path: "database/", probe: "database/roles/" },
  { name: "PKI", kind: "secrets", path: "pki/", probe: "pki/roles/", open: "#/pki" },
  { name: "Cubbyhole", kind: "secrets", path: "cubbyhole/", probe: "cubbyhole/" },
  { name: "Token", kind: "auth", path: "auth/token/", probe: "auth/token/create", open: "#/tokens" },
  { name: "Username & password", kind: "auth", path: "auth/userpass/", probe: "auth/userpass/users/", open: "#/access/userpass" },
  { name: "AppRole", kind: "auth", path: "auth/approle/", probe: "auth/approle/role/", open: "#/access/approle" },
  { name: "Kubernetes", kind: "auth", path: "auth/kubernetes/", probe: "auth/kubernetes/role/", open: "#/access/kubernetes" },
  { name: "JWT / OIDC", kind: "auth", path: "auth/jwt/", probe: "auth/jwt/role/", open: "#/access/jwt" },
  { name: "TLS certificates", kind: "auth", path: "auth/cert/", probe: "auth/cert/certs/", open: "#/access/cert" },
  { name: "LDAP", kind: "auth", path: "auth/ldap/", probe: "auth/ldap/groups/", open: "#/access/ldap" },
];

function capTags(caps) {
  const t = el("div", "tags");
  const list = caps && caps.length ? caps : ["deny"];
  for (const c of list) t.appendChild(el("span", "tag" + (c === "deny" ? " deny" : " ok"), c));
  return t;
}

async function loadDashboard() {
  const g = gen;
  kvRows($("dash-vault"), [
    ["state", vault.sealed ? "sealed" : "unsealed"],
    ["seal type", vault.type || "—"],
    ["version", vault.version || "—"],
    ["uptime", vault.uptime != null ? fmtUptime(vault.uptime) : "—"],
  ]);

  const cluster = [];
  const leader = await api("GET", "/v1/sys/leader");
  if (stale(g)) return;
  if (leader.ok && leader.body) {
    const l = leader.body;
    cluster.push(["high availability", l.ha_enabled ? "enabled" : "off (single node)"]);
    if (l.ha_enabled) {
      cluster.push(["this node", l.is_self ? "active" : "standby"]);
      cluster.push(["active node", l.leader_address || "—"]);
    }
  } else {
    cluster.push(["high availability", leader.status === 403 ? "not visible to this token" : "unknown"]);
  }
  const raft = await api("GET", "/v1/sys/storage/raft/configuration");
  if (stale(g)) return;
  if (raft.ok) {
    const servers = (raft.body && raft.body.data && raft.body.data.config && raft.body.data.config.servers) || [];
    const lead = servers.find((s) => s.leader);
    cluster.push(["storage", "integrated (Raft), experimental"]);
    cluster.push(["raft peers", servers.length + " (" + servers.filter((s) => s.voter).length + " voters)"]);
    if (lead) cluster.push(["raft leader", lead.node_id]);
  } else if (raft.status === 400) {
    cluster.push(["storage", "file or MySQL (not Raft)"]);
  } else if (raft.status === 403) {
    cluster.push(["storage", "not visible to this token"]);
  }
  kvRows($("dash-cluster"), cluster);

  const out = $("dash-engines");
  pageState(out, "loading", "Checking your token's capabilities…");
  const r = await api("POST", "/v1/sys/capabilities-self", { paths: ENGINES.map((e) => e.probe) });
  if (stale(g)) return;
  const caps = (r.ok && r.body && r.body.data) || null;
  if (!caps) { errorState(out, r, "sys/capabilities-self"); return; }
  const wrap = el("div", "table-wrap");
  const table = el("table", "grid-table");
  const thead = el("thead");
  const hr = el("tr");
  for (const h of ["Name", "Type", "Path", "Your capabilities", ""]) hr.appendChild(el("th", null, h));
  thead.appendChild(hr);
  const tbody = el("tbody");
  for (const e of ENGINES) {
    const tr = el("tr");
    const name = el("td");
    name.appendChild(e.open ? link(e.name, e.open, "entry") : el("span", null, e.name));
    const c = el("td");
    c.appendChild(capTags(caps[e.probe]));
    const act = el("td", "actions");
    if (e.open) act.appendChild(link("Open", e.open));
    tr.append(name, el("td", null, e.kind === "auth" ? "auth method" : "secrets engine"), el("td", null, e.path), c, act);
    tbody.appendChild(tr);
  }
  table.append(thead, tbody);
  wrap.appendChild(table);
  out.replaceChildren(wrap);
}

// ---- KV v2 browser ----
// Every segment is percent-encoded, and paths with "." or ".." segments are
// refused before they get here (badPath), so a crafted link cannot steer a
// request to another API path.
const encPath = (p) => p.split("/").map(encodeURIComponent).join("/");
const KV_DATA = (p) => "/v1/secret/data/" + encPath(p);
const KV_META = (p) => "/v1/secret/metadata/" + encPath(p);
const KV_UNDELETE = (p) => "/v1/secret/undelete/" + encPath(p);
const KV_DELETE_V = (p) => "/v1/secret/delete/" + encPath(p);
const KV_DESTROY = (p) => "/v1/secret/destroy/" + encPath(p);

// badPath reports a path with a "." or ".." segment (also once decoded).
const badPath = (p) => p.split("/").some((seg) => seg === "." || seg === "..");
// badName reports a policy or role name that would not stay one path segment
// once the browser normalises the URL.
const badName = (n) => n === "." || n === ".." || n.includes("/");
const BAD_NAME = "A name cannot be \".\", \"..\" or contain \"/\".";

function cleanPath(raw) {
  let p = (raw || "").trim().replace(/^\/+/, "");
  p = p.replace(/^secret\/(data|metadata)\//, ""); // tolerate a pasted full path
  return p.replace(/\/{2,}/g, "/");
}

const parentOf = (p) => p.replace(/[^/]+\/?$/, "");

function kvCrumbs(p) {
  const items = [["Secrets", "#/kv/"], ["secret", "#/kv/"]];
  let acc = "";
  const segs = p.split("/").filter(Boolean);
  segs.forEach((s, i) => {
    const isLast = i === segs.length - 1;
    acc += s + (isLast && !p.endsWith("/") ? "" : "/");
    items.push([s, kvHref(acc)]);
  });
  setCrumbs(items);
}

let kvFolderNow = "";

function kvRoute(path) {
  const p = cleanPath(path);
  closeEditor();
  if (badPath(p)) {
    setCrumbs([["Secrets", "#/kv/"], ["secret", "#/kv/"]]);
    $("kv-title").textContent = "Key/value";
    pageState($("kv-out"), "error", "A secret path cannot contain \".\" or \"..\" segments.");
    return;
  }
  kvCrumbs(p);
  $("kv-path").value = "";
  kvCreateVisibility(p === "" || p.endsWith("/") ? p : parentOf(p));
  if (p === "" || p.endsWith("/")) { kvFolderNow = p; kvFolder(p); }
  else { kvFolderNow = parentOf(p); kvSecret(p); }
}

// kvCreateVisibility shows Create secret only where the token may write.
async function kvCreateVisibility(folder) {
  const g = gen;
  const probe = "secret/data/" + folder + "new-secret";
  const caps = await can([probe]);
  if (stale(g)) return;
  $("kv-new").hidden = !allows(capsOf(caps, probe), "create", "update");
}

function goKv(p) {
  const href = kvHref(p);
  if (location.hash === href) render(); else location.hash = href;
}

async function kvFolder(p) {
  const g = gen;
  $("kv-title").textContent = p ? p : "Key/value";
  const out = $("kv-out");
  pageState(out, "loading", "Loading " + (p || "secret/") + "…");
  const probe = "secret/data/" + p + "new-secret";
  const [r, caps] = await Promise.all([api("LIST", KV_META(p)), can([probe])]);
  if (stale(g)) return;
  const canCreate = allows(capsOf(caps, probe), "create", "update");
  const createBtn = () => actionButton("Create secret", "", () => openEditor(p, null));
  if (r.status === 404 || (r.ok && !((r.body && r.body.data && r.body.data.keys) || []).length)) {
    pageState(out, "empty", p ? "Nothing under " + p + "." : "No secrets yet.", canCreate ? [createBtn()] : []);
    return;
  }
  if (!r.ok) { errorState(out, r, "secret/metadata/" + p); return; }
  const keys = r.body.data.keys.slice().sort((a, b) => {
    const fa = a.endsWith("/"), fb = b.endsWith("/");
    return fa === fb ? a.localeCompare(b) : (fa ? -1 : 1);
  });
  const wrap = el("div", "table-wrap");
  const table = el("table", "grid-table");
  const thead = el("thead");
  const hr = el("tr");
  for (const h of ["Name", ""]) hr.appendChild(el("th", null, h));
  thead.appendChild(hr);
  const tbody = el("tbody");
  for (const k of keys) {
    const child = p + k;
    const tr = el("tr");
    const td = el("td");
    const a = link("", kvHref(child), "entry");
    a.append(el("span", "kind", k.endsWith("/") ? "folder" : "secret"), el("span", null, k));
    td.appendChild(a);
    const act = el("td", "actions");
    if (!k.endsWith("/")) act.appendChild(link("Versions", kvHref(child)));
    tr.append(td, act);
    tbody.appendChild(tr);
  }
  table.append(thead, tbody);
  wrap.appendChild(table);
  const meta = el("div", "metaline", keys.length + " item" + (keys.length === 1 ? "" : "s") + " in secret/" + p);
  out.replaceChildren(meta, wrap);
}

// kvSecret shows one secret: values hidden until revealed, a JSON view and the
// version history. Revealed values live only in this view's closure, so they
// are gone as soon as the page changes.
async function kvSecret(p, version) {
  const g = gen;
  $("kv-title").textContent = p;
  const out = $("kv-out");
  pageState(out, "loading", "Loading " + p + "…");
  const [r, caps] = await Promise.all([
    api("GET", KV_DATA(p) + (version ? "?version=" + version : "")),
    can(["secret/data/" + p, "secret/delete/" + p]),
  ]);
  if (stale(g)) return;
  if (!r.ok) {
    if (r.status === 404) {
      // A soft-deleted current version is 404 on data but the metadata still
      // describes it, so fall back to metadata to show the deleted state.
      const meta = await api("GET", KV_META(p));
      if (stale(g)) return;
      if (meta.ok) { renderDeleted(p, meta.body, version); return; }
      if (meta.status === 403) {
        // Without metadata access, missing and deleted look the same here.
        pageState(out, "empty", "No readable version at " + p + ". It may not exist, or its latest " +
          "version may be deleted; your token cannot read its metadata to tell.");
        return;
      }
      pageState(out, "empty", "There is no secret at " + p + ".",
        [actionButton("Create it", "", () => openEditor(p, null, true))]);
      return;
    }
    errorState(out, r, "secret/data/" + p);
    return;
  }
  const data = (r.body && r.body.data && r.body.data.data) || {};
  const md = (r.body && r.body.data && r.body.data.metadata) || {};

  const head = el("div", "secret-head");
  head.appendChild(el("div", "metaline",
    (version ? "viewing version " + md.version : "version " + md.version) + (md.created_time ? " · created " + md.created_time : "")));
  const acts = el("div", "kv-actions");
  if (version) acts.appendChild(actionButton("Back to latest", "ghost small", () => kvSecret(p)));
  if (allows(capsOf(caps, "secret/data/" + p), "create", "update")) {
    acts.appendChild(actionButton("New version", "small", () => openEditor(p, data)));
  }
  const del = actionButton("Delete", "btn-danger small", null);
  del.hidden = !allows(capsOf(caps, "secret/delete/" + p), "update");
  del.addEventListener("click", () => confirmThen(del, "Soft-delete version " + md.version + " of " + p + "?", async () => {
    const d = await api("POST", KV_DELETE_V(p), { versions: [md.version] });
    if (!d.ok) { toast(friendlyError(d.status, d.body), "error"); return; }
    toast("Deleted version " + md.version + ".");
    kvSecret(p);
  }));
  acts.appendChild(del);
  head.appendChild(acts);

  const tabs = el("div", "tabs");
  tabs.setAttribute("role", "tablist");
  const body = el("div", "view");
  const views = { Data: () => dataView(body, data), JSON: () => jsonView(body, data), Versions: () => versionsView(body, p) };
  const buttons = Object.keys(views).map((name) => {
    const b = actionButton(name, null, () => select(name));
    b.setAttribute("role", "tab");
    b.dataset.tab = name.toLowerCase();
    return b;
  });
  function select(name) {
    for (const b of buttons) b.setAttribute("aria-selected", String(b.textContent === name));
    views[name]();
  }
  tabs.append(...buttons);
  out.replaceChildren(head, tabs, body);
  select("Data");
}

function valueText(v) { return typeof v === "string" ? v : JSON.stringify(v); }

function dataView(body, data) {
  body.replaceChildren();
  const keys = Object.keys(data);
  if (!keys.length) { pageState(body, "empty", "This version has no fields."); return; }
  const tools = el("div", "kv-actions");
  const all = actionButton("Reveal all", "ghost small", null);
  tools.appendChild(all);
  const wrap = el("div", "table-wrap");
  const table = el("table", "grid-table");
  const tbody = el("tbody");
  const toggles = [];
  for (const k of keys) {
    const tr = el("tr");
    const val = el("div", "value");
    const code = el("code", "masked", "••••••••");
    let shown = false;
    const show = (on) => {
      shown = on;
      code.textContent = on ? valueText(data[k]) : "••••••••";
      code.className = on ? "" : "masked";
      rev.textContent = on ? "Hide" : "Reveal";
    };
    const rev = actionButton("Reveal", "ghost small", () => show(!shown));
    rev.setAttribute("aria-label", "reveal " + k);
    const cp = actionButton("Copy", "ghost small", () => copy(valueText(data[k]), k));
    cp.setAttribute("aria-label", "copy " + k);
    const a = el("span", "acts");
    a.append(rev, cp);
    val.append(code, a);
    const td = el("td");
    td.appendChild(val);
    tr.append(el("th", null, k), td);
    tbody.appendChild(tr);
    toggles.push(show);
  }
  let allShown = false;
  all.addEventListener("click", () => {
    allShown = !allShown;
    for (const t of toggles) t(allShown);
    all.textContent = allShown ? "Hide all" : "Reveal all";
  });
  table.appendChild(tbody);
  wrap.appendChild(table);
  body.append(tools, wrap);
}

function jsonView(body, data) {
  body.replaceChildren();
  const masked = {};
  for (const k of Object.keys(data)) masked[k] = "********";
  const pre = el("pre", "policy-doc", JSON.stringify(masked, null, 2));
  let shown = false;
  const tools = el("div", "kv-actions");
  const rev = actionButton("Reveal values", "ghost small", () => {
    shown = !shown;
    pre.textContent = JSON.stringify(shown ? data : masked, null, 2);
    rev.textContent = shown ? "Hide values" : "Reveal values";
  });
  tools.append(rev, actionButton("Copy JSON", "ghost small", () => copy(JSON.stringify(data, null, 2), "JSON")));
  body.append(tools, pre);
}

async function versionsView(body, p) {
  const g = gen;
  pageState(body, "loading", "Loading versions…");
  const [r, caps] = await Promise.all([
    api("GET", KV_META(p)),
    can(["secret/delete/" + p, "secret/undelete/" + p, "secret/destroy/" + p]),
  ]);
  if (stale(g) || !body.isConnected) return;
  const may = (verb) => allows(capsOf(caps, "secret/" + verb + "/" + p), "update");
  if (!r.ok) { errorState(body, r, "secret/metadata/" + p); return; }
  const md = (r.body && r.body.data) || {};
  const versions = md.versions || {};
  const nums = Object.keys(versions).map(Number).sort((a, b) => b - a); // newest first
  const wrap = el("div", "table-wrap");
  const table = el("table", "grid-table history");
  const thead = el("thead");
  const hr = el("tr");
  for (const h of ["Version", "State", "Created", ""]) hr.appendChild(el("th", null, h));
  thead.appendChild(hr);
  const tbody = el("tbody");
  const op = async (url, n, what) => {
    const x = await api("POST", url, { versions: [n] });
    if (!x.ok) { toast(friendlyError(x.status, x.body), "error"); return; }
    toast(what + " version " + n + ".");
    versionsView(body, p);
  };
  for (const n of nums) {
    const v = versions[String(n)] || {};
    const state = v.destroyed ? "destroyed" : v.deleted ? "deleted" : "active";
    const tr = el("tr");
    const acts = el("td", "actions");
    if (!v.destroyed && !v.deleted) acts.appendChild(actionButton("View", "ghost small", () => kvSecret(p, n)));
    if (!v.destroyed && !v.deleted && may("delete")) acts.appendChild(actionButton("Delete", "btn-danger small", () => op(KV_DELETE_V(p), n, "Deleted")));
    if (v.deleted && !v.destroyed && may("undelete")) acts.appendChild(actionButton("Undelete", "ghost small", () => op(KV_UNDELETE(p), n, "Restored")));
    if (!v.destroyed && may("destroy")) {
      const d = actionButton("Destroy", "btn-danger small", null);
      d.addEventListener("click", () => confirmThen(d, "Destroy v" + n + " of " + p + " permanently?",
        () => op(KV_DESTROY(p), n, "Destroyed"), "destroy"));
      acts.appendChild(d);
    }
    tr.append(el("td", null, "v" + n + (n === md.current_version ? " (current)" : "")),
      el("td", null, state), el("td", null, v.created_time || "—"), acts);
    tbody.appendChild(tr);
  }
  table.append(thead, tbody);
  wrap.appendChild(table);
  body.replaceChildren(el("div", "metaline", nums.length + " version(s) · current v" + md.current_version), wrap);
}

function renderDeleted(p, body, version) {
  const md = (body && body.data) || {};
  const cv = version || md.current_version;
  const vinfo = (md.versions && md.versions[String(cv)]) || {};
  const out = $("kv-out");
  const actions = [];
  if (!vinfo.destroyed) {
    actions.push(actionButton("Undelete", "", async () => {
      const r = await api("POST", KV_UNDELETE(p), { versions: [cv] });
      if (!r.ok) { toast(friendlyError(r.status, r.body), "error"); return; }
      toast("Restored version " + cv + ".");
      kvSecret(p);
    }));
    actions.push(actionButton("New version", "ghost", () => openEditor(p, null, true)));
  }
  const s = pageState(out, "empty", vinfo.destroyed
    ? "Version " + cv + " of " + p + " is destroyed (permanently gone)."
    : "Version " + cv + " of " + p + " is soft-deleted.", actions);
  const versions = el("div", "view");
  out.appendChild(versions);
  versionsView(versions, p);
  return s;
}

// ---- KV editor (write) ----
function addFieldRow(key = "", value = "") {
  const row = el("div", "editor-row");
  const k = el("input", "k");
  k.type = "text"; k.placeholder = "key"; k.value = key; k.spellcheck = false;
  k.setAttribute("aria-label", "field name");
  const v = el("input");
  v.type = "text"; v.placeholder = "value"; v.value = value; v.spellcheck = false;
  v.setAttribute("aria-label", "field value");
  const del = actionButton("✕", "del", () => row.remove());
  del.setAttribute("aria-label", "remove field");
  row.append(k, v, del);
  $("editor-fields").appendChild(row);
  return row;
}

// openEditor opens the secret editor. With existing data it writes a new
// version of path (the path is fixed); otherwise the path is prefilled and
// editable (fixed when fixedPath is set).
function openEditor(path, existing, fixedPath) {
  const ed = $("kv-editor");
  const pathIn = $("editor-path");
  pathIn.value = path || "";
  pathIn.readOnly = !!existing || !!fixedPath;
  $("editor-title").textContent = existing ? "New version of " + path : "New secret";
  $("editor-fields").replaceChildren();
  const entries = existing ? Object.entries(existing) : [];
  if (entries.length) for (const [k, v] of entries) addFieldRow(k, valueText(v));
  else addFieldRow();
  ed.hidden = false;
  ed.scrollIntoView({ block: "nearest" });
  (pathIn.readOnly ? ed.querySelector(".editor-row input") : pathIn).focus();
}

function closeEditor() {
  $("kv-editor").hidden = true;
  $("editor-fields").replaceChildren();
}

function collectFields() {
  const data = {};
  for (const row of $("editor-fields").querySelectorAll(".editor-row")) {
    const inputs = row.querySelectorAll("input");
    const k = inputs[0].value.trim();
    if (k) data[k] = inputs[1].value;
  }
  return data;
}

async function saveSecret() {
  const p = cleanPath($("editor-path").value);
  if (badPath(p)) { toast("A secret path cannot contain . or .. segments.", "error"); $("editor-path").focus(); return; }
  if (!p || p.endsWith("/")) { toast("Enter a secret path that does not end in /.", "error"); $("editor-path").focus(); return; }
  const data = collectFields();
  if (!Object.keys(data).length) { toast("Add at least one field with a key.", "error"); return; }
  const r = await api("POST", KV_DATA(p), { data });
  if (!r.ok) { toast(friendlyError(r.status, r.body), "error"); return; }
  closeEditor();
  toast("Saved " + p + ".");
  goKv(p);
}

// ---- policies ----
const POL = (n) => "/v1/sys/policies/acl/" + encodeURIComponent(n);
const POL_LIST = "/v1/sys/policies/acl";

function polRoute(name) {
  closePolEditor();
  $("cap-out").replaceChildren();
  if (name && badName(name)) {
    setCrumbs([["Access", "#/policies"], ["Policies", "#/policies"]]);
    $("pol-title").textContent = "Policies";
    pageState($("pol-out"), "error", BAD_NAME);
    return;
  }
  if (name) {
    setCrumbs([["Access", "#/policies"], ["Policies", "#/policies"], [name, "#/policies/" + encodeURIComponent(name)]]);
    polRead(name);
  } else {
    setCrumbs([["Access", "#/policies"], ["Policies", "#/policies"]]);
    polList();
  }
}

async function polList() {
  const g = gen;
  $("pol-title").textContent = "Policies";
  const out = $("pol-out");
  pageState(out, "loading", "Loading policies…");
  const [r, caps] = await Promise.all([api("LIST", POL_LIST), can(["sys/policies/acl/new-policy"])]);
  if (stale(g)) return;
  $("pol-new").hidden = !allows(capsOf(caps, "sys/policies/acl/new-policy"), "create", "update");
  if (!r.ok) { errorState(out, r, "sys/policies/acl"); return; }
  const keys = (r.body && r.body.data && r.body.data.keys) || [];
  if (!keys.length) { pageState(out, "empty", "No policies defined."); return; }
  const wrap = el("div", "table-wrap");
  const table = el("table", "grid-table");
  const tbody = el("tbody");
  for (const k of keys) {
    const tr = el("tr");
    const td = el("td");
    td.appendChild(link(k, "#/policies/" + encodeURIComponent(k), "entry"));
    tr.appendChild(td);
    tbody.appendChild(tr);
  }
  table.appendChild(tbody);
  wrap.appendChild(table);
  out.replaceChildren(el("div", "metaline", keys.length + " polic" + (keys.length === 1 ? "y" : "ies")), wrap);
}

async function polRead(name) {
  const g = gen;
  $("pol-title").textContent = name;
  const out = $("pol-out");
  pageState(out, "loading", "Loading " + name + "…");
  const [r, caps] = await Promise.all([api("GET", POL(name)), can(["sys/policies/acl/" + name])]);
  if (stale(g)) return;
  const pc = capsOf(caps, "sys/policies/acl/" + name);
  $("pol-new").hidden = true;
  if (!r.ok) { errorState(out, r, "sys/policies/acl/" + name); return; }
  const doc = r.body && r.body.data && r.body.data.policy;
  // The policy arrives as text (as in Vault); pretty-print it when it is JSON.
  let text = typeof doc === "string" ? doc : JSON.stringify(doc, null, 2);
  try { text = JSON.stringify(JSON.parse(text), null, 2); } catch (_) { /* HCL: show as-is */ }
  const acts = el("div", "kv-actions");
  if (allows(pc, "update")) acts.appendChild(actionButton("Edit", "small", () => openPolEditor(name, text)));
  if (name !== "root" && name !== "default" && allows(pc, "delete")) {
    const del = actionButton("Delete", "btn-danger small", null);
    del.addEventListener("click", () => confirmThen(del, "Delete policy " + name + "?", () => polDelete(name)));
    acts.appendChild(del);
  }
  out.replaceChildren(acts, el("pre", "policy-doc", text));
}

function openPolEditor(name, text) {
  $("pol-name").value = name || "";
  $("pol-name").readOnly = !!name;
  $("pol-editor-title").textContent = name ? "Edit " + name : "New policy";
  $("pol-body").value = text || "";
  $("pol-editor").hidden = false;
  (name ? $("pol-body") : $("pol-name")).focus();
}

function closePolEditor() {
  $("pol-editor").hidden = true;
  $("pol-body").value = "";
}

async function polSave() {
  const n = $("pol-name").value.trim();
  const body = $("pol-body").value.trim();
  if (!n) { toast("Enter a policy name.", "error"); $("pol-name").focus(); return; }
  if (badName(n)) { toast(BAD_NAME, "error"); $("pol-name").focus(); return; }
  if (!body) { toast("The policy document is empty.", "error"); return; }
  const r = await apiRaw("PUT", POL(n), body);
  if (!r.ok) { toast(friendlyError(r.status, r.body), "error"); return; }
  closePolEditor();
  toast("Saved policy " + n + ".");
  const href = "#/policies/" + encodeURIComponent(n);
  if (location.hash === href) polRead(n); else location.hash = href;
}

async function polDelete(name) {
  if (badName(name)) { toast(BAD_NAME, "error"); return; }
  const r = await api("DELETE", POL(name));
  if (!r.ok) { toast(friendlyError(r.status, r.body), "error"); return; }
  toast("Deleted policy " + name + ".");
  location.hash = "#/policies";
}

async function capCheck() {
  const p = $("cap-path").value.trim().replace(/^\/+/, "").replace(/^v1\//, "");
  const out = $("cap-out");
  if (!p) { pageState(out, "error", "Enter a path, e.g. secret/data/app/config."); return; }
  const r = await api("POST", "/v1/sys/capabilities-self", { paths: [p] });
  if (!r.ok) { errorState(out, r, "sys/capabilities-self"); return; }
  const caps = (r.body && r.body.data && r.body.data[p]) || [];
  out.replaceChildren(el("div", "metaline", "on " + p), capTags(caps));
}

// ---- capabilities: hide what the token cannot do ----
// can asks sys/capabilities-self what the token may do on each path. On any
// failure it answers null and callers show the controls: hiding is a
// convenience, the server still enforces every call.
async function can(paths) {
  const r = await api("POST", "/v1/sys/capabilities-self", { paths });
  return r.ok && r.body && r.body.data ? r.body.data : null;
}
// allows reports whether caps (one path's list, or undefined when unknown)
// grants any of want.
const allows = (caps, ...want) => !caps || caps.includes("root") || want.some((w) => caps.includes(w));
const capsOf = (map, path) => (map ? map[path] || ["deny"] : undefined);

// ---- Access: users and roles of each auth method ----
// One description per method drives a shared list, detail and editor.
// Field types: list (comma-separated), text, duration, password (write-only),
// pem (textarea), claims (key=value lines → object).
const TOKEN_FIELDS = [
  { k: "token_policies", label: "Policies", type: "list", help: "Comma-separated. Never root." },
  { k: "token_ttl", label: "Token TTL", type: "duration", help: "e.g. 1h; empty for the default" },
  { k: "token_max_ttl", label: "Token max TTL", type: "duration" },
];
const ACCESS = {
  userpass: {
    title: "Username & password", noun: "user", base: "auth/userpass/users",
    about: "People who sign in with a username and password.",
    fields: [{ k: "password", label: "Password", type: "password", createOnly: true,
      help: "Required for a new user. On an existing user, leave empty to keep it." }, ...TOKEN_FIELDS],
    required: ["password", "token_policies"],
  },
  approle: {
    title: "AppRole", noun: "role", base: "auth/approle/role",
    about: "Machines that sign in with a role ID and a secret ID.",
    fields: [...TOKEN_FIELDS, { k: "secret_id_ttl", label: "Secret ID TTL", type: "duration" }],
    required: ["token_policies"],
  },
  kubernetes: {
    title: "Kubernetes", noun: "role", base: "auth/kubernetes/role",
    about: "Pods that sign in with their service account token.",
    fields: [
      { k: "bound_service_account_names", label: "Service accounts", type: "list" },
      { k: "bound_service_account_namespaces", label: "Namespaces", type: "list" },
      ...TOKEN_FIELDS],
    required: ["bound_service_account_names", "bound_service_account_namespaces", "token_policies"],
  },
  jwt: {
    title: "JWT / OIDC", noun: "role", base: "auth/jwt/role",
    about: "Workloads that sign in with a JWT from a trusted issuer.",
    fields: [
      { k: "bound_audiences", label: "Audiences", type: "list" },
      { k: "bound_claims", label: "Required claims", type: "claims", help: "One key=value per line" },
      ...TOKEN_FIELDS],
    required: ["token_policies"],
  },
  cert: {
    title: "TLS certificates", noun: "certificate role", base: "auth/cert/certs",
    about: "Clients that sign in with a TLS client certificate.",
    fields: [
      { k: "certificate", label: "Trusted CA or certificate (PEM)", type: "pem" },
      { k: "allowed_common_names", label: "Allowed common names", type: "list" },
      ...TOKEN_FIELDS],
    required: ["certificate", "token_policies"],
  },
  ldap: {
    title: "LDAP groups", noun: "group", base: "auth/ldap/groups",
    about: "Policies for members of an LDAP group.",
    fields: [{ k: "policies", label: "Policies", type: "list" }],
    required: ["policies"],
  },
};
const ACCESS_ORDER = ["userpass", "approle", "kubernetes", "jwt", "cert", "ldap"];
const accessHref = (m, name) => "#/access/" + m + (name ? "/" + encodeURIComponent(name) : "");
const ACCESS_URL = (m, name) => "/v1/" + ACCESS[m].base + (name ? "/" + encodeURIComponent(name) : "");

function fieldText(f, v) {
  if (v == null) return "";
  if (f.type === "list") return Array.isArray(v) ? v.join(", ") : String(v);
  if (f.type === "duration") return v === "0s" ? "" : String(v);
  if (f.type === "claims") return Object.entries(v || {}).map(([a, b]) => a + "=" + b).join("\n");
  return typeof v === "string" ? v : JSON.stringify(v);
}

let accessNow = { method: "", name: "" };

function accessRoute(method, name) {
  closeAccessEditor();
  $("access-new").hidden = true;
  if (!method) { accessIndex(); return; }
  // Own keys only: "#/access/constructor" must not reach Object.prototype.
  const m = Object.hasOwn(ACCESS, method) ? ACCESS[method] : null;
  if (!m || (name && badName(name))) {
    setCrumbs([["Access", "#/access"], ["Not found", location.hash]]);
    $("access-title").textContent = "Access";
    pageState($("access-out"), "error", m ? BAD_NAME : "There is no auth method " + method + " here.");
    return;
  }
  accessNow = { method, name };
  const crumbs = [["Access", "#/access"], [m.title, accessHref(method)]];
  if (name) crumbs.push([name, accessHref(method, name)]);
  setCrumbs(crumbs);
  if (name) accessItem(method, name); else accessList(method);
}

async function accessIndex() {
  const g = gen;
  setCrumbs([["Access", "#/access"]]);
  $("access-title").textContent = "Access";
  const out = $("access-out");
  pageState(out, "loading", "Loading auth methods…");
  const counts = await Promise.all(ACCESS_ORDER.map((m) => api("LIST", ACCESS_URL(m))));
  if (stale(g)) return;
  const wrap = el("div", "table-wrap");
  const table = el("table", "grid-table");
  const thead = el("thead");
  const hr = el("tr");
  for (const h of ["Method", "What it is for", "Entries"]) hr.appendChild(el("th", null, h));
  thead.appendChild(hr);
  const tbody = el("tbody");
  ACCESS_ORDER.forEach((m, i) => {
    const r = counts[i];
    const n = r.ok ? ((r.body && r.body.data && r.body.data.keys) || []).length
      : r.status === 404 ? 0 : null;
    const tr = el("tr");
    const td = el("td");
    td.appendChild(link(ACCESS[m].title, accessHref(m), "entry"));
    tr.append(td, el("td", null, ACCESS[m].about),
      el("td", null, n == null ? (r.status === 403 ? "not visible" : "—") : String(n)));
    tbody.appendChild(tr);
  });
  table.append(thead, tbody);
  wrap.appendChild(table);
  out.replaceChildren(wrap);
}

async function accessList(method) {
  const g = gen;
  const m = ACCESS[method];
  $("access-title").textContent = m.title;
  const out = $("access-out");
  pageState(out, "loading", "Loading…");
  const [r, caps] = await Promise.all([api("LIST", ACCESS_URL(method)), can([m.base + "/new-entry"])]);
  if (stale(g)) return;
  $("access-new").hidden = !allows(capsOf(caps, m.base + "/new-entry"), "create", "update");
  $("access-new").textContent = "Create " + m.noun;
  if (r.status === 404 || (r.ok && !((r.body && r.body.data && r.body.data.keys) || []).length)) {
    pageState(out, "empty", "No " + m.noun + "s yet. " + m.about);
    return;
  }
  if (!r.ok) { errorState(out, r, m.base); return; }
  const keys = r.body.data.keys.slice().sort();
  const wrap = el("div", "table-wrap");
  const table = el("table", "grid-table");
  const tbody = el("tbody");
  for (const k of keys) {
    const tr = el("tr");
    const td = el("td");
    td.appendChild(link(k, accessHref(method, k), "entry"));
    tr.appendChild(td);
    tbody.appendChild(tr);
  }
  table.appendChild(tbody);
  wrap.appendChild(table);
  out.replaceChildren(el("div", "metaline", keys.length + " " + m.noun + (keys.length === 1 ? "" : "s") + " · " + m.about), wrap);
}

async function accessItem(method, name) {
  const g = gen;
  const m = ACCESS[method];
  $("access-title").textContent = name;
  const out = $("access-out");
  pageState(out, "loading", "Loading " + name + "…");
  const path = m.base + "/" + name;
  const extra = method === "approle" ? [path + "/role-id", path + "/secret-id"] : [];
  const [r, caps] = await Promise.all([api("GET", ACCESS_URL(method, name)), can([path, ...extra])]);
  if (stale(g)) return;
  if (r.status === 404) { pageState(out, "empty", "There is no " + m.noun + " named " + name + "."); return; }
  if (!r.ok) { errorState(out, r, path); return; }
  const d = (r.body && r.body.data) || {};
  const c = capsOf(caps, path);
  const acts = el("div", "kv-actions");
  if (allows(c, "update")) acts.appendChild(actionButton("Edit", "small", () => openAccessEditor(method, name, d)));
  if (allows(c, "delete")) {
    const del = actionButton("Delete", "btn-danger small", null);
    del.addEventListener("click", () => confirmThen(del, "Delete " + m.noun + " " + name + "?", async () => {
      const x = await api("DELETE", ACCESS_URL(method, name));
      if (!x.ok) { toast(friendlyError(x.status, x.body), "error"); return; }
      toast("Deleted " + name + ".");
      location.hash = accessHref(method);
    }));
    acts.appendChild(del);
  }
  const table = el("table", "kv-table");
  kvRows(table, m.fields.filter((f) => f.type !== "password").map((f) => [f.label, fieldText(f, d[f.k]) || "—"]));
  out.replaceChildren(acts, table);
  if (method === "approle") {
    approleCredentials(out, name, allows(capsOf(caps, extra[0]), "read"), allows(capsOf(caps, extra[1]), "update", "create"));
  }
}

// approleCredentials shows the role ID and mints a secret ID on request (shown once).
// Each button shows only when the token may use it.
function approleCredentials(out, name, canRoleID, canSecretID) {
  if (!canRoleID && !canSecretID) return;
  const panel = el("section", "panel");
  panel.appendChild(el("h2", null, "Credentials"));
  const body = el("div", "view");
  const acts = el("div", "kv-actions");
  if (canRoleID) acts.appendChild(actionButton("Show role ID", "ghost small", async () => {
    const r = await api("GET", ACCESS_URL("approle", name) + "/role-id");
    if (!r.ok) { toast(friendlyError(r.status, r.body), "error"); return; }
    const id = (r.body && r.body.data && r.body.data.role_id) || "";
    const row = el("div", "keyrow");
    row.append(el("span", "n", "role"), el("code", null, id), actionButton("Copy", "ghost small", () => copy(id, "Role ID")));
    body.replaceChildren(row);
  }));
  const gen2 = actionButton("Generate secret ID", "small", null);
  gen2.addEventListener("click", () => confirmThen(gen2, "Issue a new secret ID for " + name + "?", async () => {
    const r = await api("POST", ACCESS_URL("approle", name) + "/secret-id", {});
    if (!r.ok) { toast(friendlyError(r.status, r.body), "error"); return; }
    const sid = (r.body && r.body.data && r.body.data.secret_id) || "";
    const row = el("div", "keyrow");
    row.append(el("span", "n", "secret"), el("code", null, sid), actionButton("Copy", "ghost small", () => copy(sid, "Secret ID")));
    body.replaceChildren(row, el("div", "warn", "Copy it now — it is shown once."));
  }));
  if (canSecretID) acts.appendChild(gen2);
  panel.append(el("p", "hint", "A machine signs in with both. The secret ID is shown once."), acts, body);
  out.appendChild(panel);
}

function openAccessEditor(method, name, existing) {
  const m = ACCESS[method];
  const ed = $("access-editor");
  ed.dataset.method = method;
  ed.dataset.existing = existing ? "1" : "";
  $("access-editor-title").textContent = existing ? "Edit " + m.noun + " " + name : "New " + m.noun;
  $("access-name").value = name || "";
  $("access-name").readOnly = !!existing;
  const box = $("access-fields");
  box.replaceChildren();
  for (const f of m.fields) {
    const wrap = el("div", "field");
    const id = "af-" + f.k;
    const lab = el("label", null, f.label + (m.required.includes(f.k) && !(existing && f.createOnly) ? " *" : ""));
    lab.htmlFor = id;
    let input;
    if (f.type === "pem" || f.type === "claims") {
      input = el("textarea");
      input.rows = f.type === "pem" ? 6 : 3;
    } else {
      input = el("input");
      input.type = f.type === "password" ? "password" : "text";
      if (f.type === "password") input.autocomplete = "new-password";
    }
    input.id = id;
    input.dataset.k = f.k;
    input.spellcheck = false;
    if (existing && f.type !== "password") input.value = fieldText(f, existing[f.k]);
    wrap.append(lab, input);
    if (f.help) wrap.appendChild(el("div", "kv-metaline", f.help));
    box.appendChild(wrap);
  }
  ed.hidden = false;
  ed.scrollIntoView({ block: "nearest" });
  (existing ? box.querySelector("input, textarea") : $("access-name")).focus();
}

function closeAccessEditor() {
  $("access-editor").hidden = true;
  $("access-fields").replaceChildren(); // drops any typed password
}

async function saveAccess() {
  const ed = $("access-editor");
  const method = ed.dataset.method;
  const m = ACCESS[method];
  const existing = ed.dataset.existing === "1";
  const name = $("access-name").value.trim();
  if (!name || badName(name)) { toast(name ? BAD_NAME : "Enter a name.", "error"); $("access-name").focus(); return; }
  const body = {};
  for (const input of $("access-fields").querySelectorAll("[data-k]")) {
    const f = m.fields.find((x) => x.k === input.dataset.k);
    const raw = input.value.trim();
    if (!raw) {
      if (m.required.includes(f.k) && !(existing && (f.createOnly || f.type === "password"))) {
        toast(f.label + " is required.", "error"); input.focus(); return;
      }
      // An emptied list or duration on an existing entry clears it; a new
      // entry simply leaves it out.
      if (existing && f.type !== "password" && f.type !== "pem") body[f.k] = f.type === "list" ? [] : f.type === "claims" ? {} : "";
      continue;
    }
    if (f.type === "list") body[f.k] = raw.split(",").map((s) => s.trim()).filter(Boolean);
    else if (f.type === "claims") {
      const obj = {};
      for (const line of raw.split("\n")) {
        const i = line.indexOf("=");
        if (i < 1) { toast("Each claim is key=value.", "error"); input.focus(); return; }
        obj[line.slice(0, i).trim()] = line.slice(i + 1).trim();
      }
      body[f.k] = obj;
    } else body[f.k] = f.type === "password" ? input.value : raw;
  }
  const r = await api("POST", ACCESS_URL(method, name), body);
  if (!r.ok) { toast(friendlyError(r.status, r.body), "error"); return; }
  closeAccessEditor();
  toast("Saved " + name + ".");
  const href = accessHref(method, name);
  if (location.hash === href) accessItem(method, name); else location.hash = href;
}

// ---- create token ----
async function tokCreate() {
  const policies = $("tok-policies").value.split(",").map((s) => s.trim()).filter(Boolean);
  const ttl = $("tok-ttl").value.trim();
  const body = { policies };
  if (ttl) body.ttl = ttl;
  const r = await api("POST", "/v1/auth/token/create", body);
  if (!r.ok) { panelMsg("tok-out", "error", friendlyError(r.status, r.body)); return; }
  const auth = (r.body && r.body.auth) || {};
  const out = $("tok-out"); out.replaceChildren();
  const reveal = el("div", "token-reveal", auth.client_token || "");
  const meta = el("div", "kv-metaline", "policies: " + ((auth.policies || []).join(", ") || "(none)") +
    (auth.lease_duration ? " · expires in ~" + fmtDuration(auth.lease_duration) : " · no expiry"));
  const acts = el("div", "kv-actions");
  acts.appendChild(actionButton("Copy token", "ghost small", () => copy(auth.client_token || "", "Token")));
  out.append(reveal, meta, el("div", "warn", "Copy it now — it is shown once."), acts);
}

// ---- PKI ----
const PKI_ROOT = "/v1/pki/root/generate/internal";
const PKI_CA = "/v1/pki/ca";
const PKI_ROLES = "/v1/pki/roles";
const PKI_ROLE = (n) => "/v1/pki/roles/" + encodeURIComponent(n);
const PKI_ISSUE = (r) => "/v1/pki/issue/" + encodeURIComponent(r);

// pemBlock renders a labeled PEM with a Copy button into out.
function pemBlock(out, label, pem) {
  const wrap = el("div", "pem");
  const head = el("div", "pem-head");
  head.append(el("span", null, label), actionButton("Copy", "ghost small", () => copy(pem, label)));
  wrap.append(head, el("pre", "policy-doc", pem));
  out.appendChild(wrap);
}

async function pkiGenerateRoot() {
  const cn = $("pki-ca-cn").value.trim();
  if (!cn) { panelMsg("pki-ca-out", "error", "Enter a common name for the root CA."); return; }
  const r = await api("POST", PKI_ROOT, { common_name: cn, key_type: "ec" });
  if (!r.ok) { panelMsg("pki-ca-out", "error", friendlyError(r.status, r.body)); return; }
  const out = $("pki-ca-out"); out.replaceChildren();
  pemBlock(out, "root CA certificate", (r.body && r.body.data && r.body.data.certificate) || "");
}

async function pkiViewCA() {
  const r = await api("GET", PKI_CA);
  if (!r.ok) { panelMsg("pki-ca-out", "error", friendlyError(r.status, r.body)); return; }
  const out = $("pki-ca-out"); out.replaceChildren();
  pemBlock(out, "CA certificate", (r.body && r.body.data && r.body.data.certificate) || "");
}

async function pkiRoleList() {
  const r = await api("LIST", PKI_ROLES);
  if (r.status === 404) { panelMsg("pki-role-out", "ok", "No roles defined."); return; }
  if (!r.ok) { panelMsg("pki-role-out", "error", friendlyError(r.status, r.body)); return; }
  const keys = (r.body && r.body.data && r.body.data.keys) || [];
  if (!keys.length) { panelMsg("pki-role-out", "ok", "No roles defined."); return; }
  const out = $("pki-role-out"); out.replaceChildren();
  const ul = el("ul", "kv-keys");
  for (const k of keys) {
    const li = el("li");
    li.appendChild(actionButton(k, "linklike", () => { $("pki-role-name").value = k; pkiRoleRead(k); }));
    ul.appendChild(li);
  }
  out.appendChild(ul);
}

async function pkiRoleRead(name) {
  const n = (name || "").trim();
  if (!n) { panelMsg("pki-role-out", "error", "Enter a role name."); return; }
  if (badName(n)) { panelMsg("pki-role-out", "error", BAD_NAME); return; }
  const r = await api("GET", PKI_ROLE(n));
  if (!r.ok) { panelMsg("pki-role-out", "error", friendlyError(r.status, r.body)); return; }
  const d = (r.body && r.body.data) || {};
  const out = $("pki-role-out"); out.replaceChildren();
  const t = el("table", "kv-table");
  kvRows(t, [
    ["allowed_domains", (d.allowed_domains || []).join(", ")],
    ["allow_subdomains", String(!!d.allow_subdomains)],
    ["max_ttl", d.max_ttl || "—"],
    ["key_type", d.key_type || "ec"],
  ]);
  const acts = el("div", "kv-actions");
  acts.appendChild(actionButton("Edit", "small", () => pkiOpenRoleEditor(n, d)));
  out.append(t, acts);
}

function pkiOpenRoleEditor(name, existing) {
  const n = (name || $("pki-role-name").value || "").trim();
  if (!n) { panelMsg("pki-role-out", "error", "Enter a role name first."); $("pki-role-name").focus(); return; }
  if (badName(n)) { panelMsg("pki-role-out", "error", BAD_NAME); return; }
  const ed = $("pki-role-editor");
  ed.dataset.name = n;
  $("pki-role-editor-name").textContent = n;
  const d = existing || {};
  $("pki-role-domains").value = (d.allowed_domains || []).join(", ");
  $("pki-role-subdomains").checked = !!d.allow_subdomains;
  $("pki-role-ttl").value = d.max_ttl && d.max_ttl !== "0s" ? d.max_ttl : "";
  $("pki-role-keytype").value = d.key_type === "rsa" ? "rsa" : "ec";
  ed.hidden = false;
}

async function pkiRoleSave() {
  const n = $("pki-role-editor").dataset.name;
  if (!n) return;
  const domains = $("pki-role-domains").value.split(",").map((s) => s.trim()).filter(Boolean);
  const body = {
    allowed_domains: domains,
    allow_subdomains: $("pki-role-subdomains").checked,
    key_type: $("pki-role-keytype").value,
  };
  const ttl = $("pki-role-ttl").value.trim();
  if (ttl) body.max_ttl = ttl;
  const r = await api("POST", PKI_ROLE(n), body);
  if (!r.ok) { panelMsg("pki-role-out", "error", friendlyError(r.status, r.body)); return; }
  $("pki-role-editor").hidden = true;
  $("pki-role-name").value = n;
  pkiRoleRead(n);
}

async function pkiIssue() {
  const role = $("pki-issue-role").value.trim();
  const cn = $("pki-issue-cn").value.trim();
  if (!role || !cn) { panelMsg("pki-issue-out", "error", "Role and common name are required."); return; }
  if (badName(role)) { panelMsg("pki-issue-out", "error", BAD_NAME); return; }
  const alt = $("pki-issue-alt").value.split(",").map((s) => s.trim()).filter(Boolean);
  const ttl = $("pki-issue-ttl").value.trim();
  const body = { common_name: cn };
  if (alt.length) body.alt_names = alt;
  if (ttl) body.ttl = ttl;
  const r = await api("POST", PKI_ISSUE(role), body);
  if (!r.ok) { panelMsg("pki-issue-out", "error", friendlyError(r.status, r.body)); return; }
  const d = (r.body && r.body.data) || {};
  const out = $("pki-issue-out"); out.replaceChildren();
  out.appendChild(el("div", "kv-metaline", "serial " + (d.serial_number || "") + (d.expiration ? " · expires " + d.expiration : "")));
  pemBlock(out, "certificate", d.certificate || "");
  pemBlock(out, "private key", d.private_key || "");
  pemBlock(out, "issuing CA", d.issuing_ca || "");
  out.appendChild(el("div", "warn", "Copy the private key now — it is shown only once."));
}

// ---- wire up ----
const onSubmit = (id, fn) => $(id).addEventListener("submit", (e) => { e.preventDefault(); fn(); });

document.addEventListener("DOMContentLoaded", async () => {
  applyTheme(storedTheme());
  reflectLoginMethod();

  $("theme-toggle").addEventListener("click", toggleTheme);
  $("skip").addEventListener("click", (e) => { e.preventDefault(); $("main").focus(); });
  $("nav-toggle").addEventListener("click", () => {
    const open = $("app").classList.toggle("nav-open");
    $("nav-toggle").setAttribute("aria-expanded", String(open));
  });
  const closeNav = () => {
    $("app").classList.remove("nav-open");
    $("nav-toggle").setAttribute("aria-expanded", "false");
  };
  $("main").addEventListener("click", closeNav);
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeNav(); });
  $("refresh").addEventListener("click", async () => { await refreshStatus(); await refreshSession(); render(); });
  $("login-method").addEventListener("change", reflectLoginMethod);
  onSubmit("login-form", login);
  onSubmit("init-form", initVault);
  onSubmit("unseal-form", submitUnsealShare);
  $("renew").addEventListener("click", renew);
  $("logout").addEventListener("click", logout);
  $("nav-signout").addEventListener("click", logout);

  // Key/value
  onSubmit("kv-form", () => {
    const p = cleanPath($("kv-path").value);
    goKv(p);
  });
  $("kv-new").addEventListener("click", () => openEditor(kvFolderNow, null));
  $("editor-add").addEventListener("click", () => addFieldRow());
  $("editor-cancel").addEventListener("click", closeEditor);
  onSubmit("kv-editor", saveSecret);

  // Policies
  $("access-new").addEventListener("click", () => openAccessEditor(accessNow.method, "", null));
  $("access-cancel").addEventListener("click", closeAccessEditor);
  onSubmit("access-editor", saveAccess);
  $("pol-new").addEventListener("click", () => openPolEditor("", ""));
  $("pol-cancel").addEventListener("click", closePolEditor);
  onSubmit("pol-editor", polSave);
  onSubmit("cap-form", capCheck);

  // Tokens
  onSubmit("tok-form", tokCreate);

  // PKI
  onSubmit("pki-ca-form", pkiGenerateRoot);
  $("pki-ca-view").addEventListener("click", pkiViewCA);
  onSubmit("pki-role-form", () => pkiRoleRead($("pki-role-name").value));
  $("pki-role-list").addEventListener("click", pkiRoleList);
  $("pki-role-new").addEventListener("click", () => pkiOpenRoleEditor($("pki-role-name").value, null));
  $("pki-role-cancel").addEventListener("click", () => { $("pki-role-editor").hidden = true; });
  onSubmit("pki-role-editor", pkiRoleSave);
  onSubmit("pki-issue-form", pkiIssue);

  window.addEventListener("hashchange", () => { render(); if (mode() === "shell") $("main").focus(); });

  await refreshStatus();
  await refreshSession();
  render();

  // Keep the seal badge current; a vault that seals sends the console back to
  // the lifecycle page.
  // A sealed vault switches at once; an unreachable one only after two polls
  // in a row fail, so one dropped request does not throw away an open editor.
  let misses = 0;
  setInterval(async () => {
    if (document.hidden || showingInitSecrets) return;
    const before = mode();
    const was = { ...vault };
    await refreshStatus();
    if (!vault.reachable && was.reachable && before === "shell") {
      misses++;
      if (misses < 2) { Object.assign(vault, was); setBadge("error", "Connection lost, retrying…"); return; }
    } else {
      misses = 0;
    }
    if (mode() !== before) { await refreshSession(); render(); }
  }, 15000);
});
