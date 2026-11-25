# uBixVault — Deployment Guide

> **Status:** beta (`v0.2.0-beta`). uBixVault is usable for real workloads but has
> not had an external security review. Read the [Security notes](#security-notes)
> before depending on it.

This guide covers running a single uBixVault node. It assumes the `ubixvault`
binary (`go build -o ubixvault ./cmd/ubixvault`).

## 1. Storage

uBixVault persists everything through a pluggable storage backend. Whatever the
backend, it holds **only ciphertext** — the barrier encrypts every value before
it is stored, so the store never sees plaintext.

### File backend (default)

Stores the encrypted data under a directory:

```sh
ubixvault server -data /var/lib/ubixvault           # -storage file is the default
```

Back this directory up (see [Backups](#6-backups)). It is single-node and its
durability rests on one disk.

### MySQL/MariaDB backend

Stores the encrypted data in a MySQL/MariaDB database, so the node becomes
**replaceable**: it can die and restart — on another host — against the same
durable, replicated database, and the database's own HA handles durability.

```sh
ubixvault server -storage mysql -storage-mysql-dsn "$UBIXVAULT_STORAGE_DSN"
# or just set $UBIXVAULT_STORAGE_DSN and pass -storage mysql
```

**Setup is minimal — the vault creates its own tables.** You only provide a
database and a user:

```sql
CREATE DATABASE ubixvault CHARACTER SET binary;
CREATE USER 'ubixvault'@'%' IDENTIFIED BY 'a-strong-password';
-- SELECT/INSERT/UPDATE/DELETE for normal operation; CREATE so the vault can
-- create its tables on first boot (you may drop CREATE afterward, or
-- pre-create the tables and never grant it).
GRANT SELECT, INSERT, UPDATE, DELETE, CREATE ON ubixvault.* TO 'ubixvault'@'%';
```

The DSN is a [go-sql-driver](https://github.com/go-sql-driver/mysql#dsn-data-source-name)
string, e.g. `ubixvault:PASSWORD@tcp(db-host:3306)/ubixvault?tls=true`.

**One active writer at a time.** Only one vault process may write to a given
database. Several replicas may share it **only with `-ha`**, which elects one
active replica through a lock in the database and fences everyone else's writes
(see [High availability](#high-availability-activestandby) below). Without `-ha`,
run exactly one process per database.

#### Securing the database credentials

The DSN contains a database username and password. Two facts shape how much this
matters, and how to protect it:

- **The blast radius is bounded.** The database stores only barrier ciphertext,
  and the master key (unseal shares / KEK) never touches the database or the DSN.
  So a leaked DSN — or a fully compromised database — yields *ciphertext, not
  secrets*. An attacker would still need the master key, which lives elsewhere.
- **It is still a credential ("secret zero").** A secrets manager needs one
  credential to start; you can shrink and protect it, not eliminate it.

Protect it, roughly weakest to strongest:

1. **Never put the DSN on the command line.** Pass it via `$UBIXVAULT_STORAGE_DSN`
   (arguments are visible in `/proc/<pid>/cmdline` and `ps`). The Helm chart does
   this for you — see below.
2. **Least privilege + TLS to the database.** Scope the user to only the
   `ubixvault` database, and use `?tls=true` in the DSN so credentials are
   encrypted in transit. (`tls=true` and `tls=skip-verify` work out of the box; a
   custom CA or client-certificate config is a planned enhancement.)
3. **On Kubernetes:** keep the DSN in a `Secret` (the chart references it by name,
   so it never appears in `values.yaml`, git, or `helm get values`), enable **etcd
   encryption-at-rest**, and restrict `get secret` RBAC on it. Optionally source
   the Secret from an external secret store (External Secrets Operator, etc.).
4. **Remove the password entirely** (strongest): MariaDB `REQUIRE X509`
   client-certificate (mTLS) auth, or cloud IAM auth / an auth-proxy sidecar
   (RDS/Cloud SQL). The DSN then carries no password.

#### Migrating an existing vault onto MySQL

Use the snapshot machinery — it round-trips the whole encrypted store through the
backend, so no data re-encryption or new tooling is needed:

```sh
# 1. Snapshot the file-backed vault (see Backups).
ubixvault operator snapshot save -token "$ROOT" backup.snapshot
# 2. Restore it into the MySQL backend (offline), then start on MySQL.
ubixvault operator snapshot restore -storage mysql -storage-mysql-dsn "$DSN" backup.snapshot
```

The same unseal shares / KEK still work — only the physical store moved.

## 2. TLS

**Always run with TLS outside of local development.** Without a certificate the
server binds to loopback only and refuses non-loopback plaintext:

```sh
# Refused — would serve secrets in the clear:
ubixvault server -listen 0.0.0.0:8200

# Correct:
ubixvault server -listen 0.0.0.0:8200 -tls-cert /etc/ubixvault/tls.crt -tls-key /etc/ubixvault/tls.key
```

`-dev-no-tls` overrides the check for trusted-network development only. Never use
it in production.

**Aborted handshakes are summarized, not logged one by one.** Load balancers and
ingress controllers health-check backends by opening a connection and closing it
without making a request. Against a TLS port that is an abandoned handshake —
either before TLS starts (a bare TCP check) or partway through it (the check
starts TLS, then disconnects). Instead of a log line per probe, the server logs a
count every 5 minutes (`N aborted TLS handshakes in the last 5m0s`). Handshakes
that fail for any other reason — a bad client certificate, an unsupported TLS
version, plain HTTP sent to the TLS port — are still logged individually.
`-log-tls-handshake-aborts` logs every abort again, for debugging a client that
never completes a connection.

A check that gets partway through TLS still costs a full handshake: the server
has already signed with its certificate key before the client leaves. The count
is therefore also a rough measure of TLS work spent on health checks. An ECDSA
(P-256) certificate makes each one far cheaper than RSA-4096; a longer check
interval on the load balancer reduces how many there are.

## 3. Unsealing

The vault starts **sealed** and cannot serve secrets until unsealed. Choose one:

**Shamir (default).** `operator init` returns *k-of-n* unseal shares; distribute
them to separate holders. After every restart, provide a threshold of shares:

```sh
ubixvault operator init -shares 5 -threshold 3      # save the keys + root token
ubixvault operator unseal <key>                     # repeat until unsealed
```

**Auto-unseal.** The master key is wrapped by a 32-byte key-encryption key (KEK),
so the server unseals itself on startup — no manual step:

```sh
export UBIXVAULT_AUTO_UNSEAL_KEY=$(head -c32 /dev/urandom | xxd -p | tr -d '\n')
ubixvault server -data /var/lib/ubixvault -auto-unseal-key "$UBIXVAULT_AUTO_UNSEAL_KEY" ...
```

The KEK protects the entire vault — store it in a secrets manager or KMS, not on
the same disk as the data.

**Transit auto-unseal.** Instead of holding a KEK locally, unseal by wrapping the
master key via another Vault-compatible **Transit** engine (uBixVault or
HashiCorp Vault). The wrapping key lives in that vault and never reaches this
host, which only needs a token authorized to encrypt/decrypt with the key:

```sh
ubixvault server -data /var/lib/ubixvault \
  -seal-transit-address https://seal-vault:8200 \
  -seal-transit-key unseal \
  -seal-transit-token "$UBIXVAULT_SEAL_TRANSIT_TOKEN"   # or the env var
```

On restart the server calls the seal vault's `transit/decrypt` to recover the
master key. If the seal vault is unreachable it stays sealed (fail-safe). Like
KEK auto-unseal, `init` returns recovery keys for root-token regeneration. In the
chart, set `sealTransit.*` (mutually exclusive with `autoUnseal`).

**External (cloud-KMS / HSM) auto-unseal.** Reach any cloud KMS (AWS/GCP/Azure)
or HSM without a provider SDK in the vault: point `-seal-external-command` at a
command that wraps/unwraps the master key. The vault invokes it in two modes,
piping raw bytes:

```
<command> [args...] wrap     # plaintext master key on stdin  -> wrapped blob on stdout
<command> [args...] unwrap   # wrapped blob on stdin          -> plaintext master key on stdout
```

Success is exit status 0 with non-empty stdout; the wrapped blob is opaque (the
command owns its format). A non-zero exit or a timeout leaves the vault **sealed**
(never fail-open). `unwrap` must emit exactly the original 32 bytes — no trailing
newline. The command's KMS/HSM credentials come from its environment (instance
role, workload identity, a mounted key), never from the vault.

```sh
ubixvault server -data /var/lib/ubixvault \
  -seal-external-command /usr/local/bin/uv-kms-seal \
  -seal-external-timeout 30s
```

Reference wrapper commands (each is a tiny script you provide — the KMS logic
lives here, not in the vault). The master key is 32 bytes, under every KMS's
direct-encrypt limit, so no envelope indirection is needed:

```sh
# AWS KMS — /usr/local/bin/uv-kms-seal
#!/bin/sh
case "$1" in
  wrap)   aws kms encrypt --key-id "$KMS_KEY_ID" --plaintext fileb:///dev/stdin \
            --query CiphertextBlob --output text | base64 -d ;;
  unwrap) aws kms decrypt --ciphertext-blob fileb:///dev/stdin \
            --query Plaintext --output text | base64 -d ;;
esac

# GCP Cloud KMS
case "$1" in
  wrap)   gcloud kms encrypt --key "$KMS_KEY" --plaintext-file - --ciphertext-file - ;;
  unwrap) gcloud kms decrypt --key "$KMS_KEY" --ciphertext-file - --plaintext-file - ;;
esac

# PKCS#11 HSM — via pkcs11-tool / openssl pkeyutl -engine pkcs11 (same shape).
```

**Image note:** the published vault image is distroless (no shell, no cloud CLI),
so the wrap command must be provided into the container — mount a static binary,
or build a derived image that bundles your provider CLI plus the script above.
Like the other auto-unseal modes, `init` returns recovery keys and only one seal
mode may be configured at a time.

Auto-unseal `init` also returns **recovery keys** (k-of-n, like Shamir shares).
The vault unseals itself with the KEK, so you never enter them to unseal — but a
threshold of them is the *only* way to regenerate a lost root token (see
[§7](#7-lost-root-token)). Save them as carefully as the KEK.

## 4. Running as a service

### systemd

```ini
# /etc/systemd/system/ubixvault.service
[Unit]
Description=uBixVault
After=network-online.target

[Service]
ExecStart=/usr/local/bin/ubixvault server \
  -listen 0.0.0.0:8200 \
  -data /var/lib/ubixvault \
  -tls-cert /etc/ubixvault/tls.crt -tls-key /etc/ubixvault/tls.key \
  -audit-log /var/log/ubixvault/audit.log
# For auto-unseal, provide the KEK via the environment (e.g. an EnvironmentFile
# with restrictive permissions, or a credential from your init system):
# Environment=UBIXVAULT_AUTO_UNSEAL_KEY=...
User=ubixvault
Group=ubixvault
Restart=on-failure
# Hardening:
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/var/lib/ubixvault /var/log/ubixvault

[Install]
WantedBy=multi-user.target
```

### Docker

The image runs as uid 65532 and does not create its data directory, so a new
Docker volume starts out owned by root and the server cannot write to it. Give
the volume to that user once, before the first start:

```sh
docker volume create ubixvault-data
docker run --rm -v ubixvault-data:/data busybox chown 65532:65532 /data

docker run -d --name ubixvault \
  -p 8200:8200 \
  -v ubixvault-data:/var/lib/ubixvault \
  -v /etc/ubixvault:/tls:ro \
  ghcr.io/ubixsys/ubixvault:1.7.0 server -listen 0.0.0.0:8200 \
    -data /var/lib/ubixvault -tls-cert /tls/tls.crt -tls-key /tls/tls.key
```

The TLS files must be readable by uid 65532 too. With a host directory instead
of a named volume, `chown 65532:65532` it the same way. (On Kubernetes the Helm
chart's pod `fsGroup` does this for you.)

Image tags are the release version without the `v` (`1.7.0`); `edge` and
`sha-<commit>` tags track unreleased builds from `main`. Provide the auto-unseal
KEK via `-e UBIXVAULT_AUTO_UNSEAL_KEY=...` (ideally from a Docker/Kubernetes
secret, not a plain env var in your compose file).

### Kubernetes (Helm)

A single-node Helm chart lives in [`deploy/charts/ubixvault`](../deploy/charts/ubixvault).
It deploys a StatefulSet with a persistent data volume, auto-unseal by default,
split TCP-liveness / HTTP-readiness probes (a sealed vault returns `503`, so an
httpGet liveness probe would crash-loop it), and the `system:auth-delegator`
binding the Kubernetes auth method needs. It runs the published image
`ghcr.io/ubixsys/ubixvault` at the chart's `appVersion` (multi-arch, built by CI
on every release tag); set `image.repository` only for an image you build
yourself from the repo-root `Dockerfile`.

```sh
kubectl create ns ubixvault
kubectl -n ubixvault create secret generic ubixvault-kek \
  --from-literal=auto-unseal-key="$(head -c32 /dev/urandom | xxd -p | tr -d '\n')"

helm install vault ./deploy/charts/ubixvault -n ubixvault \
  --set tls.existingSecret=ubixvault-tls \
  --set autoUnseal.existingSecret=ubixvault-kek
```

Then run `operator init` once inside the pod. With TLS on (the chart default),
the CLI must target HTTPS and skip verifying the cert (it is issued for the
ingress host, not localhost):

```sh
kubectl -n ubixvault exec vault-ubixvault-0 -- \
  ubixvault operator init -address https://127.0.0.1:8200 -tls-skip-verify \
    -shares 5 -threshold 3
```

Use `-ca-cert <pem>` instead of `-tls-skip-verify` to verify against a specific
CA. Without HA the chart runs one replica and refuses `replicaCount > 1`. See the
chart [README](../deploy/charts/ubixvault/README.md) for all values.

### High availability (active/standby)

With `-storage mysql -ha` (chart: `ha.enabled=true`), several replicas share one
database. Every replica unseals; the one holding a lock in the database is
**active** and the others are **standbys** that forward requests to it, so a
client can use any replica — in Kubernetes, the ordinary Service. Design and
trade-offs: [`docs/design/ha-active-standby.md`](design/ha-active-standby.md)
(ADR D-021).

- **Failover.** When the active replica shuts down — every drain, rolling
  restart or `sys/step-down` — it hands the lock over and a standby is active
  within about half a second; standbys hold requests across the handoff rather
  than failing them. When the active replica *dies*, a standby takes over once
  its lease lapses (`-ha-lock-ttl`, default 15s).
- **Replica traffic.** Replicas talk to each other on the cluster port (8201)
  with mutual TLS from a CA the vault keeps in its own barrier; there is nothing
  to configure. If you use NetworkPolicies, allow pod-to-pod TCP 8201 between the
  vault's pods.
- **Unsealing.** Each replica unseals itself. Use auto-unseal; with Shamir, every
  replica must be unsealed by hand after every restart.
- **Who is active:** `GET /v1/sys/leader` on any replica. Move the active role off
  a replica with `PUT /v1/sys/step-down` (needs a token whose policy grants
  `sys/step-down`).
- **Health.** `/v1/sys/health` returns `429` on a standby; the chart's readiness
  probe uses `?standbyok=true` so standbys are ready too.

With the chart:

```sh
helm upgrade vault ./deploy/charts/ubixvault -n ubixvault --reuse-values \
  --set storage.type=mysql --set ha.enabled=true --set replicaCount=3
```

That also adds a PodDisruptionBudget (`maxUnavailable: 1`) and soft pod
anti-affinity. **On an existing install, enable HA in the order in
[Upgrades](#8-upgrades), never in one step with a version upgrade.**

## 5. Health checks

`GET /v1/sys/health` is unauthenticated and encodes readiness in its status code
— point load balancers and liveness/readiness probes at it:

- `200` — initialized and unsealed (ready)
- `503` — sealed (not ready)
- `501` — not initialized

**Metrics.** `GET /v1/sys/metrics` returns Prometheus text-format metrics
(build info, seal state, uptime, HTTP request counts) — unauthenticated and free
of secret material, so it is safe to scrape; restrict it at the network layer as
you would any `/metrics`. The Helm chart can create a Prometheus Operator
`ServiceMonitor` (`metrics.serviceMonitor.enabled=true`).

**Web console.** A console is served at `/ui/` (`/` redirects there). It shows
the vault's seal state and lets an operator, with a token they supply in the
browser, manage KV v2 secrets (read/list/edit, version history, soft-delete /
undelete / destroy), ACL policies (list/read/write/delete), and mint scoped
tokens. The assets are static and embedded in the binary; the token is held only
in the browser tab, and every write goes through the audited `/v1` API.

## 6. Backups

Snapshots are consistent, encrypted copies of the whole store — safe to store at
rest (they contain only ciphertext). Restoring still requires the unseal shares
or the KEK.

```sh
# Back up (schedule this, e.g. via cron):
UBIXVAULT_ADDR=https://vault:8200 UBIXVAULT_TOKEN=<token> \
  ubixvault operator snapshot save /backups/ubixvault-$(date +%F).snapshot

# Restore into a fresh data directory (offline), then start the server on it:
ubixvault operator snapshot restore -data /var/lib/ubixvault-restored /backups/ubixvault-2026-07-23.snapshot
ubixvault server -data /var/lib/ubixvault-restored ...   # then unseal / auto-unseal
```

## 7. Lost root token

Recover a new root token from a quorum of keys (the vault must be unsealed):

- **Shamir mode:** use a threshold of the **unseal shares**.
- **Auto-unseal mode:** use a threshold of the **recovery keys** returned at
  `init` (the KEK unseals the vault; the recovery keys exist for exactly this).

```sh
# Over the API: POST /v1/sys/generate-root/init returns a nonce, then
# POST /v1/sys/generate-root/update with the nonce + each unseal/recovery key
# until it returns a new root_token.
```

If an auto-unseal vault was initialized before recovery-key support, it has no
recovery keys and a lost root token cannot be regenerated — reinitialize.

## 8. Upgrades

Stored entries are format-versioned, so a newer binary reads an older store.
Upgrade in place: stop the service, replace the binary, start it, and unseal (or
let auto-unseal run). **Take a snapshot first.**

With MySQL storage the database schema is versioned too. The first new-version
process to start applies any migrations (one at a time, under a lock, so
replicas starting together are safe). Migrations are forward-only: a binary
refuses to start against a database a newer version has migrated, naming both
versions. **Rolling back across a schema change therefore means restoring the
snapshot you took before upgrading.**

### Rolling upgrade of an HA deployment

1. Take a snapshot (`ubixvault operator snapshot save`, or trigger the backup
   CronJob).
2. `helm upgrade` with the new image. The StatefulSet replaces one pod at a
   time, highest ordinal first, waiting for each new pod to be ready (unsealed)
   before the next; the PodDisruptionBudget keeps a second pod from being
   disrupted meanwhile.
3. What you will see: when the pod being replaced is the active one, it steps
   down first and a standby takes over within about half a second, then it
   drains. Depending on which pod is active, the role may move more than once
   during a rollout; each move is that same sub-second handoff, and requests to
   any replica are held across it. The first new pod applies any schema
   migration; older pods keep running on an additive migration.
4. Verify: `kubectl rollout status statefulset/<release>-ubixvault`, then
   `GET /v1/sys/leader` shows an active replica on the new version.

If an old-version pod restarts *during* the rollout after a migration, it
refuses to start against the newer schema; the rollout replaces it in turn.

### Raft (integrated storage) clusters on Kubernetes

With `storage.type=raft` (see the [chart README](../deploy/charts/ubixvault/README.md#deploying-with-raft-storage))
each replica holds the data on its own volume; there is no database to migrate
and the schema rules above do not apply. The upgrade is still a rolling one.

1. Take a snapshot (`operator raft snapshot save`, or the backup CronJob) and
   check `operator raft list-peers`: every voter present and healthy.
2. `helm upgrade` with the new image. The StatefulSet replaces one pod at a
   time, highest ordinal first, and only moves on once the replaced pod is
   unsealed and ready; the PodDisruptionBudget keeps a second voter from being
   drained meanwhile. A leader being replaced transfers leadership first.
3. Wait for `kubectl rollout status`, then `list-peers` again before any other
   change. **Never roll a cluster that already has a voter down:** with 3 voters
   a second loss means no quorum.
4. Roll back by `helm rollback` the same way. Raft log and snapshot formats are
   versioned; a binary refuses data it does not understand rather than guess,
   so keep the pre-upgrade snapshot until the new version has soaked.

Operations that are not a rollout: adding a replica (mint a join token, extend
the join Secret, raise an odd `replicaCount`), removing one (`remove-peer`
first), a lost quorum (`operator raft recover`) and cluster-CA rotation
(`operator raft rotate-ca`) are described in
[the design note](design/raft-storage.md).

### Replacing a Raft replica whose volume was lost

A replica that comes back with an empty volume is a stranger wearing an old
name: the cluster's configuration still lists it as a voter, but it has none of
the log. Replace it deliberately.

1. If it was the leader, hand over first: `PUT /v1/sys/step-down`.
2. `ubixvault operator raft remove-peer <pod-name>` on any replica.
3. `ubixvault operator raft join-token` on the leader, and put the token in
   the join Secret under the pod's name (`<fullname>-N`; the chart mounts the
   Secret at `storage.raft.join.mountPath` and reads `<pod-name>` from it).
4. Delete the pod (and its PVC if it is still the damaged one). It starts,
   joins as a non-voter, catches up from a snapshot, and is promoted.
5. `operator raft list-peers`: all voters present.

**Pod `-0` is guarded.** Every pod gets the other replicas' API addresses in
`UBIXVAULT_RAFT_PEERS`. A node that would bootstrap (empty volume, no join to
make) first asks them whether a cluster already exists; if any answers
`initialized: true` it refuses to bootstrap, logs `refusing to bootstrap`, and
the pod restarts until it is given a join token as in step 3, at which point it
joins instead. Without the guard, a `-0` rescheduled onto a wiped volume would
found a second single-voter cluster under the same node ID. The guard cannot
tell "volume lost, others alive" from a first install if the others are
unreachable, so a wholly lost cluster is still restored from a snapshot
(`operator snapshot restore -storage raft`), never by letting `-0` bootstrap.

### Migrating from MySQL to Raft

Offline, one maintenance window, no dual-write (design:
[Migrating from the MySQL backend](design/raft-storage.md#migrating-from-the-mysql-backend)).
Unseal material, tokens, leases, policies and mounts are unchanged because
nothing above storage changes; the new release **must use the same auto-unseal
key (or Shamir shares)**. The whole procedure, and the rollback, are rehearsed
in CI by `test/e2e/raft/migrate.sh`.

Names below assume the release `vault` (`<fullname>` = `vault-ubixvault`).

1. **Prepare.** A recent `operator snapshot save` exists; note the KEK Secret;
   confirm the database/DSN of this instance is its own (dev and prod must not
   share a database).
2. **Freeze.** `kubectl scale statefulset <fullname> --replicas=0`. Clients
   retry (ESO/PHP resolvers already tolerate an outage). The database is now
   quiescent.
3. **Export** the ciphertext directly from the database, no unseal needed:
   `ubixvault operator raft export-mysql -storage-mysql-dsn <dsn> mysql.snap`.
   It prints the entry count and a SHA-256 over the sorted entries.
4. **Import** into pod `-0`'s volume *before it exists*: create the PVC under
   the name the StatefulSet will adopt (`data-<fullname>-0`), mount it in a
   one-shot pod running the same image as user 65532 and run
   `ubixvault operator snapshot restore -storage raft -data /var/lib/ubixvault
   -raft-node-id <fullname>-0 -raft-advertise-addr
   <fullname>-0.<fullname>-headless.<namespace>.svc:8201 mysql.snap`. The node
   ID and advertise address are persisted in the cluster configuration, so they
   must be the pod's real ones. A restore into a directory that holds Raft
   state is refused.
5. **Start Raft.** Recreate the StatefulSet (next section) with
   `storage.type=raft`, `replicaCount=3`. Pod `-0` starts from the restored
   volume, unseals with the same key and serves.
6. **Verify on `-0`:** `sys/health`, a known KV read, a login, a transit round
   trip, and `operator raft digest -against mysql.snap <snapshot-of-cluster>`:
   no entry of the export may be missing (a running cluster adds a few of its
   own and may re-encrypt some; they are listed).
7. **Join `-1` and `-2`:** a join token each, in the join Secret; wait for both
   to be promoted (`operator raft list-peers`).
8. **Soak** with the MySQL database untouched and unreferenced (dev: at least a
   week; prod: two weeks and one full backup cycle).

**Recreating the StatefulSet.** `volumeClaimTemplates` and `serviceName` are
immutable, and the MySQL-mode set has neither a data volume nor a headless
Service, so a plain `helm upgrade` is refused. Two ways, both rehearsed:

| | Same release (`--cascade=orphan`) | Parallel release |
| --- | --- | --- |
| Steps | scale to 0, `kubectl delete statefulset <fullname> --cascade=orphan`, `helm upgrade --set storage.type=raft ...` | `helm install vault-raft ...` next to the old, which stays scaled to 0 |
| Names | unchanged: Service, Ingress, NetworkPolicy, PDB, backup CronJob, node names | new release name: Service DNS name changes; Ingress host moves by values |
| Rollback | restore a Raft snapshot into the emptied database, delete the Raft StatefulSet with `--cascade=orphan`, `helm upgrade --set storage.type=mysql ...` | restore a Raft snapshot into the emptied database, scale the old StatefulSet back up |
| Helm history | one release; `helm rollback` cannot cross the StatefulSet change, use the steps above | two releases; the old is untouched until deleted |

**Recommendation: the same release.** The design requires that the namespaces,
Services and Ingress do not change and that clients are not touched; only that
path keeps them. Use the parallel release when something in-cluster addresses
the Service by DNS name and cannot be repointed in the window, or when an
untouched, instantly restartable old release is worth more than keeping the
names. (`migrate.sh` measures the client-visible outage of both; the figures are
in the design note once the first CI run has produced them.)

**Rollback** (until the soak ends): snapshot Raft
(`operator raft snapshot save`: it carries every write since cutover), empty the
database (`DROP DATABASE`/`CREATE DATABASE` — destructive, an operator action),
`operator snapshot restore -storage mysql -storage-mysql-dsn <dsn> <file>`, then
bring the `storage.type=mysql` release back as in the table. No secret, token
or lease is invalidated in either direction.

### Enabling HA on an existing single-replica install

A replica from before HA takes no lock and fences nothing, so it must never run
against the database at the same time as HA replicas. Do it in separate steps:

1. Take a snapshot.
2. Upgrade to an HA-capable release **as-is** — one replica, `ha.enabled=false`.
   Confirm it is healthy.
3. `--set ha.enabled=true`, still `replicaCount=1`. The pod restarts with `-ha`
   and becomes active; `GET /v1/sys/leader` reports `"ha_enabled": true`.
4. `--set replicaCount=3`. New pods unseal and join as standbys.
5. Prove a handoff before relying on it: `PUT /v1/sys/step-down` (or delete the
   active pod) and watch `sys/leader` move.

To go back to one replica: scale to 1 first, then set `ha.enabled=false`.

## 9. Verifying released images

Published images are **keyless-signed with [cosign](https://github.com/sigstore/cosign)**
and carry an **SPDX SBOM attestation**, both produced in CI via GitHub OIDC and
bound to the image digest. Verify a release before deploying:

```sh
IMAGE=ghcr.io/ubixsys/ubixvault:1.7.0
IDENTITY='https://github.com/ubixsys/ubixvault/.github/workflows/image.yml@refs/tags/v1.7.0'

# Verify the signature came from this repo's release workflow.
cosign verify "$IMAGE" \
  --certificate-identity "$IDENTITY" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com

# Verify and extract the SBOM attestation.
cosign verify-attestation "$IMAGE" --type spdxjson \
  --certificate-identity "$IDENTITY" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  | jq -r '.payload | @base64d | fromjson | .predicate' > sbom.spdx.json
```

Use `--certificate-identity-regexp 'https://github.com/ubixsys/ubixvault/.*'`
instead of the exact identity to accept any tag. A failed verification means the
image is not a genuine, unmodified release — do not deploy it.

## 10. Client token hygiene

Every login mints a token, and a token is a **live credential until it expires or is
revoked** — and a stored record in the vault until then. A client that logs in on
every request and drops the token leaves one behind per request. In one deployment
that was ~15,000 tokens a day, 176,000 in all, next to about 50 rows of real data,
each valid for 32 days.

Build clients like this:

- **Don't log in per request.** Log in once per process (or per pod) and reuse the
  token until it nears expiry — or, better, **cache the secrets you read** for a few
  minutes in process or shared memory (e.g. APCu under PHP-FPM) and only go back to
  the vault when the cache expires. This also keeps a brief vault outage from failing
  your requests.
- **Revoke what you mint.** If a client logs in only to read a few secrets, call
  `POST /v1/auth/token/revoke-self` straight after. Every token may revoke itself
  without a policy grant. Never revoke a static, operator-issued token — it is not
  the client's to end.
- **Give roles a short `ttl`.** Set `ttl` on the auth role a client logs in through
  (Kubernetes, AppRole, userpass, …) to how long it actually needs the token —
  minutes for a bootstrap that reads and discards. A token that is never revoked then
  stops being valid soon after. Kubernetes roles honor `ttl` from 1.4.0.
- **Renewal is bounded.** `renew-self` never extends a token past its ceiling: its
  own TTL or `-max-token-ttl` (default `768h`), whichever is longer (ADR D-022).

The server deletes expired tokens in the background (every 10 minutes, on the active
replica), so a backlog clears on its own as tokens expire. To see whether clients are
piling tokens up, count the token records in the storage table:

```sql
SELECT COUNT(*) FROM ubixvault_kv WHERE vault_key LIKE 'sys/token/%';
```

A count that climbs with request volume means a client is logging in per request.

## Security notes

- **Not production-hardened / no external security review.** Treat accordingly.
- Run **behind TLS**; never expose plaintext over a network.
- Protect the **unseal shares** and the **auto-unseal KEK** — they are the keys to
  everything. Losing all of them means unrecoverable data.
- Use **separate instances per environment** (sandbox / dev / prod). Do not share
  one instance across trust boundaries.
- Issue **scoped tokens** with least-privilege policies; avoid using the root
  token for routine work.
- Enable **audit logging** (`-audit-log`) and monitor it; note that a full or
  unavailable audit sink is fail-closed and will stop the vault from serving.
- Consider **rate limiting** (`-rate-limit <req/s>`) to blunt brute-force against
  unseal shares and tokens. Behind a proxy, add `-rate-limit-trust-forwarded`
  (chart: `rateLimit.trustForwarded`) so limits key on the real client rather
  than the proxy IP. Health, metrics, and the console are exempt.
- **Pass secrets by environment, not flags.** The auto-unseal KEK and the
  transit-seal token accept flags for convenience, but a value on the command
  line is visible in the process list (`ps`). Prefer the environment variables
  (`UBIXVAULT_AUTO_UNSEAL_KEY`, `UBIXVAULT_SEAL_TRANSIT_TOKEN`) — which is what
  the Helm chart uses (sourced from Secrets).
