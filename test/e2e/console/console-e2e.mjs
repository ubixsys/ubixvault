// End-to-end test of the /ui/ console: drives it in headless Chrome over the
// DevTools protocol (no dependencies — Node >= 22 for the built-in WebSocket).
// Run it through run.sh (or `make console-e2e`), which starts a fresh,
// uninitialized server for it.
//
// usage: node console-e2e.mjs <vault-base-url> <screenshot-dir>
import { spawn } from "node:child_process";
import { writeFileSync, mkdtempSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const BASE = process.argv[2];
const OUT = process.argv[3];
const CHROME = process.env.CHROME_BIN || [
  "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
  "/usr/bin/google-chrome", "/usr/bin/google-chrome-stable", "/usr/bin/chromium", "/usr/bin/chromium-browser",
].find((p) => existsSync(p));
if (!CHROME) { console.error("no Chrome found; set CHROME_BIN"); process.exit(2); }
const PORT = 9333;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
let failures = 0;
const check = (name, ok, detail = "") => {
  console.log(`${ok ? "ok  " : "FAIL"} ${name}${detail ? "  — " + detail : ""}`);
  if (!ok) failures++;
};

const profile = mkdtempSync(join(tmpdir(), "cdp-"));
const chromeArgs = ["--headless=new", `--remote-debugging-port=${PORT}`, `--user-data-dir=${profile}`,
  "--window-size=1280,900", "--no-first-run", "about:blank"];
if (process.env.CI) chromeArgs.push("--no-sandbox"); // CI containers lack the sandbox's kernel features
const chrome = spawn(CHROME, chromeArgs, { stdio: "ignore" });

async function target() {
  for (let i = 0; i < 50; i++) {
    try {
      const r = await fetch(`http://127.0.0.1:${PORT}/json/new?${encodeURIComponent(BASE + "/ui/")}`, { method: "PUT" });
      if (r.ok) return await r.json();
    } catch (_) { /* not up yet */ }
    await sleep(200);
  }
  throw new Error("chrome devtools did not come up");
}

const t = await target();
const ws = new WebSocket(t.webSocketDebuggerUrl);
await new Promise((res) => ws.addEventListener("open", res, { once: true }));
let seq = 0;
const pending = new Map();
const consoleErrors = [];
ws.addEventListener("message", (ev) => {
  const m = JSON.parse(ev.data);
  if (m.id && pending.has(m.id)) { pending.get(m.id)(m); pending.delete(m.id); }
  if (m.method === "Runtime.exceptionThrown") consoleErrors.push(m.params.exceptionDetails.exception?.description || m.params.exceptionDetails.text);
  if (m.method === "Log.entryAdded" && m.params.entry.level === "error" && /Content Security Policy|Refused/.test(m.params.entry.text)) consoleErrors.push(m.params.entry.text);
});
const send = (method, params = {}) => new Promise((res) => { const id = ++seq; pending.set(id, res); ws.send(JSON.stringify({ id, method, params })); });
const js = async (expr) => {
  const r = await send("Runtime.evaluate", { expression: `(async () => { ${expr} })()`, awaitPromise: true, returnByValue: true });
  if (r.result && r.result.exceptionDetails) throw new Error("page error: " + JSON.stringify(r.result.exceptionDetails.exception?.description || r.result.exceptionDetails.text));
  return r.result?.result?.value;
};
const shot = async (name) => {
  const r = await send("Page.captureScreenshot", { format: "png" });
  writeFileSync(join(OUT, name + ".png"), Buffer.from(r.result.data, "base64"));
};
const visible = (id) => js(`const e = document.getElementById(${JSON.stringify(id)}); return !!e && !e.hidden && e.offsetParent !== null;`);
const text = (id) => js(`return document.getElementById(${JSON.stringify(id)}).textContent;`);
const settle = () => sleep(700);
const submit = (formId) => js(`document.getElementById(${JSON.stringify(formId)}).requestSubmit(); return true;`);
const setVal = (id, v) => js(`const e = document.getElementById(${JSON.stringify(id)}); e.value = ${JSON.stringify(v)}; e.dispatchEvent(new Event("change")); return true;`);
const mode = () => js(`return document.getElementById("app").dataset.mode;`);
const go = async (hash) => { await js(`location.hash = ${JSON.stringify(hash)}; return true;`); await settle(); };
// clickText clicks the first button (or link) inside scope whose text starts with label.
const clickText = (scope, label) => js(`
  const b = [...document.querySelectorAll(${JSON.stringify(scope + " button, " + scope + " a")})].find(x => x.textContent.trim().startsWith(${JSON.stringify(label)}));
  if (!b) return false; b.click(); return true;`);
const inner = (sel) => js(`const e = document.querySelector(${JSON.stringify(sel)}); return e ? e.innerText : "";`);

await send("Page.enable");
await send("Runtime.enable");
await send("Log.enable");
await sleep(1500);

// ---- 1. uninitialized: only Initialize shows, no navigation
check("uninitialized: lifecycle mode", (await mode()) === "lifecycle", await mode());
check("uninitialized: Initialize panel shown", await visible("init-panel"));
check("uninitialized: Unseal panel hidden", !(await visible("unseal-panel")));
check("uninitialized: no sidebar", !(await visible("sidebar")));
await shot("01-uninitialized");

// ---- 2. initialize 3 shares / threshold 2
await setVal("init-shares", "3");
await setVal("init-threshold", "2");
await submit("init-form");
await sleep(1500);
const keys = await js(`return [...document.querySelectorAll("#init-out .keys")].map(l => [...l.querySelectorAll("code")].map(c => c.textContent));`);
check("init: 3 key shares shown", keys && keys[0] && keys[0].length === 3, keys ? `${keys[0]?.length} shares` : "none");
check("init: root token shown", keys && keys[1] && /^uv\./.test(keys[1][0] || ""));
check("init: keys stay visible after init", await visible("init-panel"));
check("init: Unseal panel now shown (sealed)", await visible("unseal-panel"));
check("init: progress starts at 0 of 2", (await text("unseal-progress")) === "0 of 2", await text("unseal-progress"));
await shot("02-initialized-keys");
const [shares, [root]] = keys;

// ---- 3. hide the secrets
await clickText("#init-out", "I've stored");
await settle();
check("hide: Initialize panel gone", !(await visible("init-panel")));
check("hide: no key material left in the page", !(await js(`return document.body.innerText.includes(${JSON.stringify(shares[0])});`)));

// ---- 4. unseal with two shares
await setVal("unseal-key", shares[0]);
await submit("unseal-form");
await settle();
check("unseal: share 1 accepted, 1 of 2", (await text("unseal-progress")) === "1 of 2", await text("unseal-progress"));
check("unseal: input cleared after submit", (await js(`return document.getElementById("unseal-key").value;`)) === "");
await shot("03-unseal-progress");
await setVal("unseal-key", "not-a-share");
await submit("unseal-form");
await settle();
check("unseal: a bad share is reported", /Request failed|key|invalid/i.test(await text("unseal-out")), await text("unseal-out"));
await setVal("unseal-key", shares[1]);
await submit("unseal-form");
await sleep(1200);
check("unseal: vault unsealed", (await text("seal-word")) === "Unsealed", await text("seal-word"));
check("unseal: sign-in page shown", (await mode()) === "signin" && (await visible("page-signin")), await mode());
check("unseal: badge says Unsealed", (await text("seal-badge-text")).startsWith("Unsealed"), await text("seal-badge-text"));

// ---- 5. sign in with the root token → dashboard
const methods = () => js(`return [...document.getElementById("login-method").options].map(o => o.value).join(",");`);
check("sign-in: a fresh vault offers only Token", (await methods()) === "token", await methods());
check("sign-in: the method picker is hidden with one method", !(await visible("login-method")));
await setVal("login-method", "token");
check("sign-in: token field shown for Token method", await visible("login-token"));
check("sign-in: username hidden for Token method", !(await visible("login-user")));
await setVal("login-token", root);
await submit("login-form");
await sleep(1200);
check("sign-in (token): shell mode", (await mode()) === "shell", await mode());
check("sign-in (token): dashboard shown", await visible("page-dashboard"));
check("sign-in (token): sidebar shown", await visible("sidebar"));
check("sign-in (token): who-am-I shows root", (await text("whoami-table")).includes("root"));
check("sign-in (token): button says Forget token", (await text("logout")) === "Forget token", await text("logout"));
check("dashboard: nav marks Dashboard", (await js(`return document.querySelector('#nav a[aria-current="page"]')?.dataset.nav;`)) === "dashboard");
check("dashboard: cluster card says not Raft", (await text("dash-cluster")).includes("not Raft"), await text("dash-cluster"));
const engines = await inner("#dash-engines");
check("dashboard: engines listed with root capability", engines.includes("Key/value") && engines.includes("LDAP") && engines.includes("root"), engines.slice(0, 120));
await shot("04-dashboard-dark");

// ---- 6. KV browser: empty, create, masked, reveal, JSON, versions
await go("#/kv/");
check("kv: page shown", await visible("page-kv"));
check("kv: empty state", (await inner("#kv-out .state.empty")).includes("No secrets yet"), await inner("#kv-out"));
await js(`document.getElementById("kv-new").click(); return true;`);
await settle();
check("kv: editor opens", await visible("kv-editor"));
await setVal("editor-path", "app/config");
await js(`const r = document.querySelector("#editor-fields .editor-row"); const [k, v] = r.querySelectorAll("input"); k.value = "db_password"; v.value = "s3cret-e2e"; return true;`);
await js(`document.getElementById("editor-add").click(); const rows = document.querySelectorAll("#editor-fields .editor-row"); const [k, v] = rows[1].querySelectorAll("input"); k.value = "user"; v.value = "app"; return true;`);
await submit("kv-editor");
await sleep(1200);
check("kv: saved, routed to the secret", (await js(`return location.hash;`)) === "#/kv/app/config", await js(`return location.hash;`));
check("kv: values masked by default", !(await inner("#kv-out")).includes("s3cret-e2e"));
check("kv: breadcrumbs show the path", (await inner("#crumbs")).replace(/\s+/g, "").includes("secret/app/config"), await inner("#crumbs"));
await shot("05-kv-secret-masked");
await clickText("#kv-out", "Reveal all");
await sleep(200);
check("kv: Reveal all shows values", (await inner("#kv-out")).includes("s3cret-e2e"));
await clickText("#kv-out .tabs", "JSON");
await sleep(200);
check("kv: JSON view masks values", (await inner("#kv-out pre")).includes("********") && !(await inner("#kv-out pre")).includes("s3cret-e2e"));
await clickText("#kv-out", "Reveal values");
await sleep(200);
check("kv: JSON reveal shows values", (await inner("#kv-out pre")).includes("s3cret-e2e"));
await go("#/policies");
check("kv: revealed values leave the DOM when the page changes", !(await js(`return document.documentElement.innerHTML.includes("s3cret-e2e");`)));
await go("#/kv/");
check("kv: revealed values are gone after navigating", !(await js(`return document.body.innerText.includes("s3cret-e2e");`)));
check("kv: folder lists app/", (await inner("#kv-out")).includes("app/"), await inner("#kv-out"));
await go("#/kv/app/");
check("kv: folder app/ lists config", (await inner("#kv-out")).includes("config"));
await shot("06-kv-folder");

// write a second version through the editor, then use the versions tab
await go("#/kv/app/config");
await clickText("#kv-out", "New version");
await settle();
check("kv: new-version editor keeps the path fixed", await js(`return document.getElementById("editor-path").readOnly;`));
await js(`const v = document.querySelector("#editor-fields .editor-row input:not(.k)"); v.value = "rotated-e2e"; return true;`);
await submit("kv-editor");
await sleep(1200);
check("kv: second version written", (await inner("#kv-out .metaline")).includes("version 2"), await inner("#kv-out .metaline"));
await clickText("#kv-out .tabs", "Versions");
await settle();
const hist = await inner("#kv-out .history");
check("kv: versions table shows v2 current and v1", hist.includes("v2 (current)") && hist.includes("v1"), hist.replace(/\s+/g, " ").slice(0, 160));
await clickText("#kv-out .history", "Destroy");
await sleep(200);
await clickText("#kv-out .history .confirm", "Yes");
await sleep(400);
check("kv: destroy needs the typed word", (await inner("#kv-out .history")).includes("active"), "still not destroyed without typing");
await js(`const i = document.querySelector("#kv-out .history .confirm input"); i.value = "destroy"; return true;`);
await clickText("#kv-out .history .confirm", "Yes");
await settle();
check("kv: v2 destroyed after typed confirm", (await inner("#kv-out .history")).includes("destroyed"), (await inner("#kv-out .history")).replace(/\s+/g, " ").slice(0, 160));
await shot("07-kv-versions");
await go("#/kv/app/%2E%2E/%2E%2E/sys/policies/acl");
check("kv: dot segments in a link are refused", (await inner("#kv-out .state.error")).includes("cannot contain"), await inner("#kv-out"));
await go("#/kv/missing/secret");
check("kv: missing secret shows empty state", (await inner("#kv-out .state")).includes("There is no secret"), await inner("#kv-out"));

// ---- 7. policies: create, read, check a path
await go("#/policies");
check("policies: empty state on a fresh vault", (await inner("#pol-out .state.empty")).includes("No policies"), await inner("#pol-out"));
await js(`document.getElementById("pol-new").click(); return true;`);
await setVal("pol-name", "readers");
await setVal("pol-body", JSON.stringify({ path: { "secret/data/app/*": { capabilities: ["read"] }, "secret/metadata/*": { capabilities: ["list"] } } }));
await submit("pol-editor");
await sleep(1200);
check("policies: saved and routed", (await js(`return location.hash;`)) === "#/policies/readers", await js(`return location.hash;`));
check("policies: document shown", (await inner("#pol-out pre")).includes("secret/data/app/*"));
await go("#/policies/..");
check("policies: a dot-segment name in a link is refused", (await inner("#pol-out .state.error")).includes("cannot be"), await inner("#pol-out"));
await go("#/policies/readers");
await setVal("cap-path", "secret/data/app/config");
await submit("cap-form");
await settle();
check("policies: check a path (root)", (await inner("#cap-out")).includes("root"), await inner("#cap-out"));
await go("#/policies");
check("policies: list shows the new policy", (await inner("#pol-out")).includes("readers"), await inner("#pol-out"));
await shot("08-policy");

// ---- 7b. access: users and roles
await go("#/access");
const accessIdx = await inner("#access-out");
check("access: index lists the auth methods", accessIdx.includes("Username & password") && accessIdx.includes("AppRole") && accessIdx.includes("LDAP groups"), accessIdx.slice(0, 160));
await go("#/access/userpass");
check("access: empty userpass list", (await inner("#access-out .state.empty")).includes("No users yet"), await inner("#access-out"));
check("access: Create user shown to root", await visible("access-new"));
await js(`document.getElementById("access-new").click(); return true;`);
await settle();
await setVal("access-name", "bob");
await setVal("af-password", "pw-bob-e2e");
await setVal("af-token_policies", "readers");
await setVal("af-token_ttl", "1h");
await submit("access-editor");
await sleep(1200);
check("access: user saved and opened", (await js(`return location.hash;`)) === "#/access/userpass/bob", await js(`return location.hash;`));
const bob = await inner("#access-out");
check("access: user detail shows policies and TTL, never the password", bob.includes("readers") && bob.includes("1h") && !bob.includes("pw-bob-e2e"), bob.replace(/\s+/g, " ").slice(0, 160));
await clickText("#access-out", "Edit");
await settle();
check("access: edit keeps the name fixed", await js(`return document.getElementById("access-name").readOnly;`));
await setVal("af-token_policies", "readers, default");
await submit("access-editor");
await sleep(1200);
check("access: edit without a password keeps the user", (await inner("#access-out")).includes("default"), await inner("#access-out"));
const bobLogin = await fetch(BASE + "/v1/auth/userpass/login/bob", { method: "POST", body: JSON.stringify({ password: "pw-bob-e2e" }) });
check("access: the password still works after the edit", bobLogin.status === 200, String(bobLogin.status));
await go("#/access/userpass");
await js(`document.getElementById("access-new").click(); return true;`);
await settle();
await setVal("access-name", "bob");
await setVal("af-password", "pw-overwritten");
await setVal("af-token_policies", "readers");
await submit("access-editor");
await sleep(1200);
const dupToast = await inner("#toast");
const bobAgain = await fetch(BASE + "/v1/auth/userpass/login/bob", { method: "POST", body: JSON.stringify({ password: "pw-bob-e2e" }) });
check("access: create refuses an existing name and keeps its password", dupToast.includes("already exists") && bobAgain.status === 200, dupToast + " " + bobAgain.status);
await js(`document.getElementById("access-cancel").click(); return true;`);
await shot("08b-access-user");

// LDAP answers 200 for a missing group, so it gets its own existence checks.
await go("#/access/ldap/ghost");
check("access: a missing LDAP group is not found", (await inner("#access-out .state.empty")).includes("no group named ghost"), await inner("#access-out"));
await go("#/access/ldap");
await js(`document.getElementById("access-new").click(); return true;`);
await settle();
await setVal("access-name", "ops");
await setVal("af-policies", "readers");
await submit("access-editor");
await sleep(1200);
check("access: a new LDAP group is created", (await js(`return location.hash;`)) === "#/access/ldap/ops" && (await inner("#access-out")).includes("readers"), await inner("#access-out"));

await go("#/access/approle");
await js(`document.getElementById("access-new").click(); return true;`);
await settle();
await setVal("access-name", "ci");
await setVal("af-token_policies", "default");
await submit("access-editor");
await sleep(1200);
check("access: approle role saved", (await js(`return location.hash;`)) === "#/access/approle/ci");
await clickText("#access-out", "Show role ID");
await settle();
check("access: role ID shown", /[0-9a-f-]{20,}/.test(await inner("#access-out .keyrow code")), await inner("#access-out .keyrow"));
await clickText("#access-out", "Generate secret ID");
await sleep(200);
await clickText("#access-out .confirm", "Yes");
await settle();
check("access: secret ID shown once", (await inner("#access-out")).includes("shown once"), await inner("#access-out"));
await go("#/access/userpass/bob");
await clickText("#access-out", "Delete");
await sleep(200);
await clickText("#access-out .confirm", "Yes");
await settle();
check("access: user deleted, back on the list", (await js(`return location.hash;`)) === "#/access/userpass" && !(await inner("#access-out")).includes("bob"), await inner("#access-out"));
await go("#/access/nope");
check("access: unknown method", (await inner("#access-out .state.error")).includes("no auth method"), await inner("#access-out"));
await go("#/access/constructor");
check("access: inherited name is not a method", (await inner("#access-out .state.error")).includes("no auth method"), await inner("#access-out"));

// ---- 8. deep link survives a reload; light theme
await go("#/kv/app/config");
await send("Page.reload");
await sleep(2000);
check("reload: deep link lands on the secret", (await visible("page-kv")) && (await inner("#kv-title")) === "app/config", await inner("#kv-title"));
const themeState = () => js(`return (document.documentElement.dataset.theme || "system") + "|" + document.getElementById("theme-toggle").textContent;`);
check("theme: follows the system by default", (await themeState()) === "system|Theme: System", await themeState());
await js(`document.getElementById("theme-toggle").click(); return true;`);
check("theme: first click is Light", (await themeState()) === "light|Theme: Light", await themeState());
await go("#/");
await shot("09-dashboard-light");
await js(`document.getElementById("theme-toggle").click(); return true;`);
check("theme: second click is Dark", (await themeState()) === "dark|Theme: Dark", await themeState());
await js(`document.getElementById("theme-toggle").click(); return true;`);
check("theme: third click goes back to System", (await themeState()) === "system|Theme: System", await themeState());
check("theme: System clears the stored choice", (await js(`return localStorage.getItem("ubixvault.theme");`)) === null);
await go("#/nowhere");
check("router: unknown page shows Not found", await visible("page-notfound"));

// ---- 9. a reader: denied states, then userpass sign in and out
const mk = await fetch(BASE + "/v1/auth/userpass/users/alice", { method: "POST", headers: { "X-Vault-Token": root },
  body: JSON.stringify({ password: "pw-console-e2e", policies: ["readers"] }) });
check("setup: userpass user created", mk.status === 204, String(mk.status));
// The sign-in methods are cached for up to 10 s; wait until the new user shows.
for (let i = 0; i < 30; i++) {
  const m = await (await fetch(BASE + "/v1/sys/internal/ui/mounts")).json();
  if (m.data && m.data.auth && m.data.auth["userpass/"]) break;
  await sleep(500);
}
await go("#/");
await js(`document.getElementById("logout").click(); return true;`);
await settle();
check("forget: pasted root token only forgotten", /not revoked/i.test(await text("session-out")), await text("session-out"));
check("forget: back on the sign-in page", (await mode()) === "signin");
const rootStill = await fetch(BASE + "/v1/auth/token/lookup-self", { headers: { "X-Vault-Token": root } });
check("forget: root token still valid on the server", rootStill.status === 200, String(rootStill.status));

check("sign-in: userpass offered once it has a user, LDAP still not", (await methods()) === "userpass,token", await methods());
check("sign-in: the method picker shows with two methods", await visible("login-method"));
await setVal("login-method", "userpass");
await setVal("login-user", "alice");
await setVal("login-pass", "wrong");
await submit("login-form");
await settle();
check("sign-in (userpass): wrong password gets the uniform message", /Sign-in failed/.test(await text("session-out")), await text("session-out"));
check("sign-in (userpass): password field cleared", (await js(`return document.getElementById("login-pass").value;`)) === "");
await setVal("login-user", "alice");
await setVal("login-pass", "pw-console-e2e");
await submit("login-form");
await sleep(1200);
const who = await text("whoami-table");
check("sign-in (userpass): who-am-I shows the user", who.includes("alice") && who.includes("readers"), who.replace(/\s+/g, " ").slice(0, 120));
check("sign-in (userpass): button says Sign out", (await text("logout")) === "Sign out");
const reader = await inner("#dash-engines");
check("reader: engines show deny where no grant", reader.includes("deny"), reader.slice(0, 120));
await go("#/policies");
await go("#/access/userpass");
check("reader: users page is denied and offers no Create", (await inner("#access-out .state.denied")).includes("not allowed") && !(await visible("access-new")), await inner("#access-out"));
await go("#/policies");
check("reader: policies page shows the denied state", (await inner("#pol-out .state.denied")).includes("not allowed"), await inner("#pol-out"));
await fetch(BASE + "/v1/secret/data/app/config", { method: "POST", headers: { "X-Vault-Token": root },
  body: JSON.stringify({ data: { db_password: "v3-e2e" } }) });
await go("#/kv/app/config");
check("reader: no New version or Delete on a read-only secret", !(await js(`return [...document.querySelectorAll("#kv-out button")].some(b => !b.hidden && (b.textContent === "New version" || b.textContent === "Delete"));`)));
check("reader: no Create secret on a read-only folder", !(await visible("kv-new")));
check("reader: can read the secret it is granted", !(await inner("#kv-out .state.denied")) && (await inner("#kv-out")).includes("db_password"), await inner("#kv-out"));
await shot("10-reader-secret");
await go("#/kv/app/other");
check("reader: a path it cannot see says so", (await inner("#kv-out .state")).includes("cannot read"), await inner("#kv-out"));
const aliceToken = await js(`return sessionStorage.getItem("ubixvault.token");`);
await js(`document.getElementById("nav-signout").click(); return true;`);
await settle();
check("sign out: says the token was revoked", /revoked/i.test(await text("session-out")), await text("session-out"));
const dead = await fetch(BASE + "/v1/auth/token/lookup-self", { headers: { "X-Vault-Token": aliceToken } });
check("sign out: the token is really revoked on the server", dead.status === 403, String(dead.status));

// ---- 10. narrow screen: the sidebar becomes a menu
await send("Emulation.setDeviceMetricsOverride", { width: 390, height: 844, deviceScaleFactor: 2, mobile: true });
await setVal("login-method", "token");
await setVal("login-token", root);
await submit("login-form");
await sleep(1200);
check("narrow: menu button shown", await visible("nav-toggle"));
check("narrow: no horizontal scroll", await js(`return document.documentElement.scrollWidth <= window.innerWidth;`),
  String(await js(`return document.documentElement.scrollWidth;`)));
await js(`document.getElementById("nav-toggle").click(); return true;`);
await sleep(400);
await shot("11-narrow-menu");
await send("Emulation.clearDeviceMetricsOverride");

check("no page errors or CSP violations", consoleErrors.length === 0, consoleErrors.join(" | ").slice(0, 300));

ws.close();
chrome.kill();
console.log(failures ? `\n${failures} FAILED` : "\nALL PASSED");
process.exit(failures ? 1 : 0);
