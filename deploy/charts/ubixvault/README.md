# uBixVault Helm chart

Deploys uBixVault to Kubernetes: one replica by default, or several in
active/standby HA over MySQL storage (`ha.enabled`).

> The 1.x API is stable ([VERSIONING](../../../docs/VERSIONING.md)); an external
> security review has **not** happened yet and is tracked separately. Weigh that
> before trusting it with production secrets.

## Prerequisites

- Kubernetes ≥ 1.24
- A container image built from the repo-root `Dockerfile`, pushed somewhere your
  cluster can pull. No image is published yet — build and push your own:

  ```sh
  docker build -t <your-registry>/ubixvault:0.2.0-beta.1 \
    --build-arg VERSION=0.2.0-beta.1 .
  docker push <your-registry>/ubixvault:0.2.0-beta.1
  ```
- A `StorageClass` for the encrypted data volume (or an existing PVC).
- For TLS: either a `kubernetes.io/tls` Secret, or cert-manager.

## Install

```sh
# Minimal (TLS via an existing Secret, auto-unseal via an existing Secret):
helm install vault ./deploy/charts/ubixvault \
  --namespace ubixvault-prod \
  --set image.repository=<your-registry>/ubixvault \
  --set tls.existingSecret=ubixvault-tls \
  --set autoUnseal.existingSecret=ubixvault-kek
```

Create the auto-unseal KEK Secret first (32 random bytes, 64 hex chars):

```sh
kubectl -n ubixvault-prod create secret generic ubixvault-kek \
  --from-literal=auto-unseal-key="$(head -c32 /dev/urandom | xxd -p | tr -d '\n')"
```

Then **initialize once** — see the post-install notes (`helm status`), or:

```sh
kubectl -n ubixvault-prod exec -it vault-ubixvault-0 -- \
  ubixvault operator init -shares 5 -threshold 3    # save the shares + root token
```

## Deploying with MySQL storage

Run the vault against a MySQL/MariaDB database so the node is replaceable. The
example below uses the production environment (`ubixvault-prod`,
`vault.prod.ubixsys.com`); for dev, substitute `ubixvault-dev`,
`vault.dev.ubixsys.com`, and the `tls-wildcard-ubixsys-dev` secret. Ordered runbook:

```sh
NS=ubixvault-prod          # or ubixvault-dev

# 1. Namespace: managed in the kube-stuff/kubernetes repo (namespaces/$NS.yml),
#    labeled cert-manager-tls: tls-prod (or tls-dev) so Replikate syncs the
#    matching *.ubixsys.com wildcard TLS secret into it.

# 2. Prepare the database — the vault creates its own tables, you create the DB + user.
#    On your MariaDB:
#      CREATE DATABASE ubixvault CHARACTER SET binary;
#      CREATE USER 'ubixvault'@'%' IDENTIFIED BY 'STRONG-PASSWORD';
#      GRANT SELECT, INSERT, UPDATE, DELETE, CREATE ON ubixvault.* TO 'ubixvault'@'%';

# 3. Secrets: the DSN and the auto-unseal KEK (never put these in values/git).
kubectl -n "$NS" create secret generic ubixvault-db \
  --from-literal=dsn='ubixvault:STRONG-PASSWORD@tcp(MARIADB-HOST:3306)/ubixvault?tls=true'
kubectl -n "$NS" create secret generic ubixvault-kek \
  --from-literal=auto-unseal-key="$(head -c32 /dev/urandom | xxd -p | tr -d '\n')"

# 4. Install (DSN comes from the Secret; no data PVC is provisioned).
helm upgrade --install vault ./deploy/charts/ubixvault -n "$NS" \
  --set image.tag=0.2.0-beta.10 \
  --set storage.type=mysql --set storage.mysql.dsnSecret=ubixvault-db \
  --set autoUnseal.existingSecret=ubixvault-kek \
  --set tls.existingSecret=tls-wildcard-ubixsys-prod \
  --set ingress.enabled=true \
  --set ingress.host=vault.prod.ubixsys.com \
  --set ingress.tlsSecret=tls-wildcard-ubixsys-prod

# 5. Initialize once — SAVE the recovery keys and root token (shown once).
kubectl -n "$NS" exec -it vault-ubixvault-0 -- ubixvault operator init

# 6. Verify: it auto-unseals from the KEK; readiness turns green once unsealed.
kubectl -n "$NS" exec -it vault-ubixvault-0 -- \
  ubixvault operator seal-status -tls-skip-verify -address https://127.0.0.1:8200
```

Because storage is the database, there is **no data PVC** and the pod can be
rescheduled freely — it reconnects to the same store and auto-unseals. Enable
scheduled backups afterward (see [Backups](#backups)) once you have created a
least-privilege `sys/snapshot` token Secret.

## Deploying with Raft storage

`storage.type=raft` runs the vault on its own replicated storage: every replica
keeps a full copy on its own PVC and the cluster elects the active replica, so
no external database is needed. It implies HA. Design and trade-offs:
[`docs/design/raft-storage.md`](../../../docs/design/raft-storage.md).

What the chart creates: a StatefulSet (`OrderedReady`, one PVC per pod, node ID
= pod name), a headless Service `<fullname>-headless` giving each pod a stable
DNS name (the address recorded in the Raft configuration), the PodDisruptionBudget,
and with `storage.networkPolicy.enabled` a NetworkPolicy that limits the cluster
port to the vault pods. `replicaCount` must be odd (3 recommended).

```sh
# 1. Secrets: the auto-unseal KEK (a restarted replica must unseal unattended)
kubectl -n $NS create secret generic ubixvault-kek \
  --from-literal=auto-unseal-key="$(openssl rand -hex 32)"

# 2. Install. Pod -0 starts, bootstraps a one-node cluster and waits to be
#    initialised; pods -1 and -2 are not created until -0 is ready.
helm install vault deploy/charts/ubixvault -n $NS \
  --set storage.type=raft --set replicaCount=3 \
  --set ha.antiAffinity=hard \
  --set tls.existingSecret=ubixvault-tls --set autoUnseal.existingSecret=ubixvault-kek

# 3. Initialise once on -0 — SAVE the recovery keys and root token.
kubectl -n $NS exec vault-ubixvault-0 -- ubixvault operator init -address https://127.0.0.1:8200 -tls-skip-verify

# 4. Admit the other pods: one single-use token each (15 min by default), in a
#    Secret with one key per pod. The joiners retry until the Secret appears.
for i in 1 2; do
  kubectl -n $NS exec vault-ubixvault-0 -- ubixvault operator raft join-token \
    -address https://127.0.0.1:8200 -tls-skip-verify -token "$ROOT"   # prints "Join token: <t>"
done
kubectl -n $NS create secret generic vault-ubixvault-raft-join \
  --from-literal=vault-ubixvault-1=<token-1> --from-literal=vault-ubixvault-2=<token-2>

# 5. Verify (each pod joins as a non-voter, catches up, is promoted to voter).
kubectl -n $NS exec vault-ubixvault-0 -- ubixvault operator raft list-peers \
  -address https://127.0.0.1:8200 -tls-skip-verify -token "$ROOT"
```

`-tls-skip-verify` is only for these in-pod calls to `127.0.0.1` (the certificate
does not name it); use `-ca-cert` from outside. The Secret name is `<fullname>-raft-join` unless
`storage.raft.join.tokenSecret` is set; the key must equal the pod name.

Things to know:

- **Bootstrap is by ordinal.** Every pod gets the same `-raft-retry-join` list,
  naming pod `-0`; a node drops its own address from it, so `-0` bootstraps and
  the rest join. This relies on a server with the self-skip rule (the release
  that introduced `storage.type=raft` in this chart).
- **A wiped volume does not re-bootstrap.** Every pod gets
  `UBIXVAULT_RAFT_PEERS` (the other replicas' API addresses). A pod that would
  bootstrap on an empty volume first asks them; if one reports an initialized
  cluster it refuses (`refusing to bootstrap`) and restarts until the Secret
  holds a join token under its name, then joins. Replace it with `remove-peer`
  first; see `docs/DEPLOYMENT.md`, "Replacing a Raft replica whose volume was lost".
- **TLS to the leader.** Joiners reach `-0` at
  `<fullname>-0.<fullname>-headless.<ns>.svc`. The API certificate must cover
  that name, and if it does not chain to system roots set
  `storage.raft.join.leaderCASecret` (a Secret holding the CA, key
  `storage.raft.join.leaderCASecretKey`).
- **Storage.** Block storage with honest `fsync`; never NFS/SMB.
  `storage.raft.persistence.size` defaults to 10Gi. `persistence.*` (file
  backend) is not used.
- **Scale down** with `operator raft remove-peer` first, then lower
  `replicaCount`. A PVC outlives its pod: delete it explicitly when a node is
  gone for good.
- **Switching an existing install** to raft recreates the StatefulSet
  (`volumeClaimTemplates` and `serviceName` are immutable) — follow the
  migration steps in the design doc, not a plain `helm upgrade`.
- **Recovery and CA rotation** (`operator raft recover`, `rotate-ca`): see the
  design doc.

## Design notes

- **StatefulSet.** With file storage: 1 replica and a `volumeClaimTemplate` for
  the encrypted data directory. `replicaCount > 1` is refused unless
  `ha.enabled` (which requires MySQL storage).
- **HA (`ha.enabled`).** Every replica unseals; the one holding a lock in the
  database is active and the others forward to it over the cluster port (8201,
  mutual TLS from a CA the vault manages itself — no certificates to supply).
  The chart then passes `-ha` and the pod IP (`POD_IP`), exposes the cluster
  port, probes readiness with `/v1/sys/health?standbyok=true` (standbys are
  ready: they serve by forwarding), adds a PodDisruptionBudget
  (`maxUnavailable: 1`) and soft pod anti-affinity. A drain or rolling restart
  hands the active role over in about half a second. Enabling it on an existing
  install and upgrading it: follow the order in
  [DEPLOYMENT.md § Upgrades](../../../docs/DEPLOYMENT.md#8-upgrades).
- **Auto-unseal first.** In Kubernetes, Shamir unseal after every restart is
  painful, so auto-unseal (a KEK in a Secret) is the default. Shamir still works
  — set `autoUnseal.enabled=false` and unseal manually via `kubectl exec`.
- **Probes are split on purpose.** A sealed vault returns `503` on
  `/v1/sys/health`. Liveness and startup therefore use `/v1/sys/livez`, which
  answers `200` whenever the process serves, sealed or not, so a sealed-but-alive
  pod is not crash-looped; **readiness** uses `/v1/sys/health`, so only an
  unsealed vault receives traffic (with HA, `?standbyok=true`: standbys too).
- **Kubernetes auth method.** When `kubernetesAuth.enabled` (default), the
  release's ServiceAccount is bound to `system:auth-delegator` so the vault can
  validate pod ServiceAccount tokens via TokenReview.
- **TLS.** With `tls.enabled` (default) the server serves HTTPS from a mounted
  Secret. Disabling TLS requires `devNoTLS=true` and is INSECURE.
- **Audit is off by default** and fail-closed: enable it with a dedicated volume
  (`audit.enabled=true`), never sharing the data disk.
- **Ingress is optional and encrypted end to end.** When `ingress.enabled`, the
  Ingress is annotated `backend-protocol: HTTPS` so ingress-nginx re-encrypts to
  the vault (which serves HTTPS) — the ingress never sees plaintext secrets. A
  secrets manager is sensitive: prefer internal access, or lock it down with
  `ingress.whitelistSourceRange`.
- **Hardened pod:** non-root (uid 65532), read-only root filesystem, all
  capabilities dropped, `RuntimeDefault` seccomp.

## Key values

| Key | Default | Description |
|-----|---------|-------------|
| `replicaCount` | `1` | 1 unless `ha.enabled`; then 3 is recommended. |
| `ha.enabled` | `false` | Active/standby HA; requires `storage.type=mysql` or `raft` (raft implies it). |
| `storage.type` | `file` | `file`, `mysql` or `raft`. |
| `storage.raft.persistence.size` | `10Gi` | Per-replica Raft volume (`.storageClass`, `.accessModes` too). |
| `storage.raft.join.tokenSecret` | `<fullname>-raft-join` | Secret with one single-use join token per joining pod, keyed by pod name. |
| `storage.raft.join.leaderCASecret` | `""` | CA the joiners verify the leader's API certificate against. |
| `storage.networkPolicy.enabled` | `false` | Raft only: cluster port from the vault pods only. |
| `ha.clusterPort` | `8201` | Replica-to-replica port (mutual TLS). |
| `ha.lockTTL` / `ha.retryInterval` | `15s` / `500ms` | Unplanned failover bound / standby lock retry. |
| `ha.podDisruptionBudget.enabled` / `.maxUnavailable` | `true` / `1` | PDB when HA is on. |
| `ha.antiAffinity` | `soft` | `soft`, `hard` or `none`; ignored if `affinity` is set. |
| `terminationGracePeriodSeconds` | `30` | Time to step down and drain on shutdown. |
| `image.repository` | `ghcr.io/ubixsys/ubixvault` | Official image published by the ubixsys org. |
| `image.tag` | `""` | Defaults to the chart `appVersion`. |
| `persistence.enabled` / `.size` | `true` / `1Gi` | Encrypted data volume. |
| `autoUnseal.enabled` | `true` | Wrap the master key with a KEK for self-unseal. |
| `autoUnseal.existingSecret` | `""` | Secret holding the KEK (key `auto-unseal-key`). |
| `sealTransit.enabled` | `false` | Unseal through another Vault-compatible Transit engine instead. |
| `sealExternal.enabled` | `false` | Unseal through a command that calls your KMS or HSM (see below). |
| `sealExternal.command` / `.args` / `.timeout` | `""` / `[]` / `30s` | Absolute path in the container, arguments before `wrap`/`unwrap`, per-call timeout. |
| `sealExternal.helper.image` / `.command` / `.mountPath` | `""` / `[]` / `/seal/bin` | Init container that copies the command into a shared volume. |
| `sealExternal.volumes` / `.volumeMounts` | `[]` / `[]` | Extra volumes for the vault container, e.g. provider credentials. |
| `tls.enabled` | `true` | Serve HTTPS. |
| `tls.existingSecret` | `""` | `kubernetes.io/tls` Secret to mount. |
| `tls.certManager.enabled` | `false` | Issue the cert via cert-manager instead. |
| `devNoTLS` | `false` | Allow plaintext on a non-loopback address (INSECURE). |
| `audit.enabled` | `false` | Fail-closed audit log; use a dedicated volume. |
| `kubernetesAuth.enabled` | `true` | Bind SA to `system:auth-delegator`. |
| `service.type` / `.port` | `ClusterIP` / `8200` | In-cluster Service. |
| `ingress.enabled` | `false` | Expose over an Ingress (requires `tls.enabled`). |
| `ingress.host` | `""` | Hostname, e.g. `vault.prod.ubixsys.com`. |
| `ingress.tlsSecret` | `""` | TLS Secret in this namespace (e.g. a Replikate-synced wildcard). |
| `ingress.whitelistSourceRange` | `""` | Optional CIDR allow-list to restrict access. |

See [`values.yaml`](values.yaml) for the full list.

## Unsealing through your KMS or HSM (`sealExternal`)

The vault runs `<command> [args...] wrap` and `... unwrap` with the key on stdin and
reads the result from stdout; a failed or timed-out call leaves it sealed. The image
is distroless, so ship the command as a static binary in a helper image; the init
container copies it into a shared volume before the vault starts. Exactly one of
`autoUnseal`, `sealTransit` and `sealExternal` may be on.

```sh
helm install ubixvault ./deploy/charts/ubixvault -n $NS \
  --set tls.existingSecret=$TLS \
  --set autoUnseal.enabled=false \
  --set sealExternal.enabled=true \
  --set sealExternal.command=/seal/bin/kms-seal \
  --set 'sealExternal.args={--key-id,alias/ubixvault}' \
  --set sealExternal.helper.image=registry.example/kms-seal:1.0.0 \
  --set 'sealExternal.helper.command={cp,/kms-seal,/seal/bin/}'
```

Provider credentials come from `extraEnv` (for example `valueFrom.secretKeyRef`) or
from a Secret mounted with `sealExternal.volumes` and `sealExternal.volumeMounts`.
Prefer workload identity (IRSA, GKE Workload Identity, Azure Workload Identity)
through `serviceAccount` annotations so no long-lived key is stored.

## Backups

Snapshots are encrypted ciphertext and safe to store at rest; a restore still
requires the unseal shares or the KEK.

### Manual snapshot

```sh
kubectl -n ubixvault-prod exec -it vault-ubixvault-0 -- \
  ubixvault operator snapshot save /var/lib/ubixvault/backup.snapshot
```

### Scheduled off-node backups (`backup.enabled`)

A CronJob runs `operator snapshot save` against the running vault on a schedule
and writes the snapshot to a **separate PVC** — put it on a network-backed
`storageClass` so the backup survives loss of the vault's node. This keeps the
latest snapshot (timestamped history + object-storage upload are a planned
follow-up).

It needs a token authorized for `sys/snapshot`. Create a least-privilege policy
and token, then a Secret:

```sh
# 1. A policy that allows only taking a snapshot.
cat > backup.json <<'EOF'
{"path": {"sys/snapshot": {"capabilities": ["create", "update"]}}}
EOF
curl -sf -H "X-Vault-Token: $ROOT" -X PUT \
  "$VAULT/v1/sys/policies/acl/backup" --data @backup.json

# 2. A token bound to that policy.
TOKEN=$(curl -sf -H "X-Vault-Token: $ROOT" -X POST \
  "$VAULT/v1/auth/token/create" -d '{"policies":["backup"]}' \
  | jq -r .auth.client_token)

# 3. A Secret the CronJob reads.
kubectl -n ubixvault-prod create secret generic uv-backup-token \
  --from-literal=token="$TOKEN"
```

Then enable it:

```sh
helm upgrade vault ./deploy/charts/ubixvault \
  --reuse-values \
  --set backup.enabled=true \
  --set backup.tokenSecret=uv-backup-token \
  --set backup.schedule="0 */6 * * *" \
  --set backup.persistence.storageClass=<network-backed-class>
```

### Restoring (test this before you need it)

Restore is offline — the server must not be running against the target
directory. Copy the snapshot out of the backup PVC, then:

```sh
ubixvault operator snapshot restore -data ./restored /path/to/ubixvault.snapshot
# start the server on ./restored and unseal as usual
```

See the top-level [`docs/DEPLOYMENT.md`](../../../docs/DEPLOYMENT.md).
