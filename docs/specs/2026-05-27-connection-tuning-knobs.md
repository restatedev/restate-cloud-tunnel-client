# Spec: connection tuning knobs for hub deployments

## Goal

The operator runs the tunnel client as a centralized per-`RestateCloudEnvironment`
Deployment (a hub shared by all `RestateDeployment`s), not a sidecar. The
connection counts are currently hardcoded with sidecar assumptions. Expose them
as static config so an operator (human or the k8s operator) can size a hub.

This is about connection multiplicity for throughput / NLB-IP / core spread.
There is no 200-stream bottleneck on the tunnel client's paths: both the cloud
ingress server and the tunnel client's `serve()` advertise
`max_concurrent_streams = u32::MAX`, so a single connection already carries
unlimited concurrent streams.

## Knobs

All defaults preserve current behavior exactly (no idle-connection regression
for low-traffic deployments).

| Option (kebab TOML) / env | Type | Default | Effect |
|---|---|---|---|
| `environment-proxy-connections` / `RESTATE_ENVIRONMENT_PROXY_CONNECTIONS` | NonZeroUsize | 6 | Outbound H2 connections to the cloud; applied to both the ingress (:8080) and admin (:9070) proxies |
| `tunnel-server-connections` / `RESTATE_TUNNEL_SERVER_CONNECTIONS` | NonZeroUsize | 1 | Inbound tunnel connections opened to each resolved tunnel server |
| `environment-proxy` / `RESTATE_ENVIRONMENT_PROXY` | bool | true | Renamed from `remote-proxy`; serde `alias = "remote-proxy"` keeps the old name working |

`pools-per-tunnel` (existing, default 16) is unchanged.

`environment-proxy-connections` applies to both the ingress and admin proxies for
simplicity. Admin is control-plane / low-traffic, so 6 is already generous there;
sizing it up together with ingress is wasteful but harmless. Split into two knobs
only if a real asymmetry shows up.

## Implementation

### `options.rs`
- Rename the toggle `remote_proxy` -> `environment_proxy`. In `OptionsShadow` it
  MUST be `Option<bool>` with
  `#[serde(alias = "remote-proxy", skip_serializing_if = "Option::is_none")]`,
  mirroring the existing `auth_token` / `bearer-token` field. Resolve the `true`
  default after `extract()` when building `Options` (`Options.environment_proxy:
  bool`).

  Why not a plain `bool`: a non-`Option` default is serialized by
  `Serialized::defaults` under the renamed key `environment-proxy`, while the
  operator's `RESTATE_REMOTE_PROXY` arrives as the aliased key `remote-proxy`.
  Both then exist in the merged figment dict and serde rejects them as a duplicate
  field, so `Options::load` fails closed on every operator-managed pod. Verified
  against figment 0.10.19 / serde in this repo: plain-`bool` errors with
  `duplicate field environment-proxy`; `Option<bool>` + `skip_serializing_if`
  extracts cleanly. (The existing `RESTATE_REMOTE_PROXY` works today only because
  the default key and the env key are the same string; the rename splits them.)
- Add `environment_proxy_connections: NonZeroUsize` and
  `tunnel_server_connections: NonZeroUsize` to both structs. These can stay
  non-`Option` (like `pools_per_tunnel`): they have no aliased env key, so the
  default key and the env key are identical and override in place - no collision.
- `OptionsShadow::default()`: `environment_proxy: None`,
  `environment_proxy_connections: 6`, `tunnel_server_connections: 1`.
- Reject configurations that set both `environment-proxy` and `remote-proxy`
  before serde extraction, with a friendly error matching the existing
  `auth-token` / `bearer-token` migration guard. This includes the env/env case
  (`RESTATE_ENVIRONMENT_PROXY` + `RESTATE_REMOTE_PROXY`) and mixed file/env
  cases.

### `main.rs` outbound (trivial)
- Replace both `NonZeroUsize::new(6).unwrap()` literals (the ingress and admin
  `round_robin_client` calls) with `options.environment_proxy_connections`.
- Replace `options.remote_proxy` with `options.environment_proxy`.

### `main.rs` inbound (the substantive change)
Open `tunnel_server_connections` connections per resolved server instead of one.

- Restructure the tracking map from
  `HashMap<Uri, (CancellationToken, watch::Receiver<TunnelStatus>)>` to
  `HashMap<Uri, ServerConnections>` where:
  ```rust
  struct ServerConnections {
      token: CancellationToken,                       // per-server; cancels all N tasks
      statuses: Vec<watch::Receiver<TunnelStatus>>,
  }
  ```
  Update `HealthState.uris` to the same type.
- The no-change fast path stays keyed on server URIs (compare keys + len).
- For each new server:
  - Build the local-service clients (`alpn_client`, `http2_client`) once and
    wrap them so they are **shared** across the N connection tasks (e.g. `Arc`),
    so local pools stay at `pools_per_tunnel` per server, not per connection.
    `http1_client` is already shared. Note this means the N inbound connections
    multiplex onto the same downstream pool set: it bounds connections *per local
    destination* at `pools_per_tunnel` (it does **not** bound the number of
    distinct destinations - each pool connects per-authority, so distinct local
    pods are unbounded). For a hub fanning heavy concurrent traffic at a single
    local service, raise `pools_per_tunnel` alongside `tunnel_server_connections`.
  - Create one per-server `token = token.child_token()`.
  - For `i in 0..tunnel_server_connections`: make a status channel and a
    `token.child_token()`, build the `Handler` (clone of the shared clients),
    and spawn `handle_tunnel_uri` with metrics scoped to `(authority, i)`.
    Collect the receivers into `statuses`.
- Teardown (`retain`): cancel the per-server `token` (cancels all N children)
  and call `remove_tunnel(authority, tunnel_server_connections)`.

### `metrics.rs`
- Add a `connection` label (the index, as a string) to `opened`, `draining`, and
  `connection_attempts`, so the N tasks per server no longer share a series.
  Labeling the counter too costs the same cardinality as the gauges and keeps a
  single flapping/reconnecting connection visible in attempts; aggregate with
  `sum without (connection)` for a per-server view.
- `tunnel(server, connection_index)` sets the label pair for all three; per-
  connection `opened(bool)` / `draining(bool)` no longer clobber each other.
- `remove_tunnel(server, count)` removes all three series for indices `0..count`.
  Removing `connection_attempts` bounds cardinality for SRV churn at the cost of
  resetting that counter if a removed server later reappears.
- This is a breaking metric schema change: even at the default
  `tunnel-server-connections = 1`, `opened`, `draining`, and
  `connection_attempts` gain `connection="0"`. Release notes and any dashboards
  or alerts should aggregate with `sum without (connection)` when they need the
  old per-server view.
- Add request-level metrics for performance diagnosis:
  - `requests_total{server,connection,direction,status}` with
    `direction = inbound|outbound` and `status = ok|error`;
  - `request_duration_seconds{server,connection,direction}` with buckets
    `[0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30]`;
  - `requests_inflight{server,connection,direction}`;
  - `local_handler_duration_seconds{instance}` with the same buckets;
  - `local_handler_inflight{instance}`.

  Request duration is measured until upstream response headers are received. The
  local-handler metrics are measured from forwarding to the local handler until
  response headers are received. Stream-level rejection reasons and RTT require
  lower-level h2/hyper hooks and are follow-up work, not part of this PR.

### health (`main.rs`)
- Aggregate the N connection statuses per server with a deterministic precedence,
  reporting the highest present: `Open > Opening > Draining > BackingOff >
  Cancelled`. `HealthOutput` stays keyed by `Uri`.
- `started` readiness latch is unchanged: any connection open anywhere -> started.

## Inbound throughput: cloud-side behavior

Confirmed in the cloud tunnel-server code: within a single tunnel-server process,
each proxied request selects a ready live connection for the
`(environment_id, tunnel_name)` at request time. So multiple connections landing
on the same process are utilized. This is not a global cross-pod tunnel map; the
benefit and evenness across cloud ingress pods still depend on NLB/request
routing and where the connections terminate.

The multi-pod-hub precedent is **not** a proof: those connections terminate on
different ingress pods by construction, whereas N connections from one pod are not
guaranteed to spread across ingress pods (the NLB hashes on source ip:port -
distinct source ports can spread, but nothing guarantees distinct ingress pods),
and the cloud still must choose among a tunnel's live connections when pushing.

Sizing: total inbound connections = (number of resolved tunnel servers) x
`tunnel_server_connections`. On a region that resolves to multiple tunnel IPs the
default of 1 is already more than one connection.

## Operator integration

No restate-operator code change is required to use the two connection-count
knobs: they pass through the rce's `tunnel.env` as
`RESTATE_TUNNEL_SERVER_CONNECTIONS` /
`RESTATE_ENVIRONMENT_PROXY_CONNECTIONS`. Surfacing a first-class operator field
(e.g. `tunnelServerConnections` beside `replicas`) is a possible follow-up, out of
scope here.

The renamed proxy toggle is different. The current operator always emits
`RESTATE_REMOTE_PROXY`, so operator-managed deployments should continue using
that name for now. Adding `RESTATE_ENVIRONMENT_PROXY` via `tunnel.env` while the
operator also emits `RESTATE_REMOTE_PROXY` is intentionally rejected by the
dual-key guard. Actually switching to the new env var requires a coordinated
operator change: upgrade tunnel-client images first so they understand
`RESTATE_ENVIRONMENT_PROXY`, then change the operator to emit only the new name
and never both names in the same pod.

## Out of scope
- `worker_threads`: `available_parallelism()` already honors the pod's cgroup CPU
  limit. Revisit as an env-only knob if a real need appears.
- The operator-side "sidecar tunnel" option (lives in restate-operator).

## Testing
- `options.rs` tests (these must run serially or with isolated env, since they set
  process env vars):
  - defaults resolve as expected (`environment_proxy = true`, connections 6 / 1);
  - env override of each new knob;
  - **regression for the collision**: with `RESTATE_REMOTE_PROXY=false` set,
    `Options::load` succeeds and yields `environment_proxy = false` (this is the
    case that fails with a plain `bool`);
  - `RESTATE_ENVIRONMENT_PROXY=false` also works;
  - setting both `environment-proxy` and `remote-proxy` fails with a friendly
    error before serde reports a duplicate field.
- Existing `parse_tunnel_destination` tests are unaffected.
- Manual: with `tunnel_server_connections=N`, confirm N connections per server and
  N `opened` series per server; with `environment_proxy_connections=M`, confirm M
  outbound connections.
