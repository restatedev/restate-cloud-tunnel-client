# Restate Cloud Tunnel Client

This repository manages a client intended to establish tunnelling connections from your compute infrastructure
to your Restate Cloud environment, such that your environment can talk to Restate SDK services running in your
private network. In addition, the client can serve on ports 8080 and 9070, providing unauthenticated access to
your Restate Cloud environment (see 'Environment proxy' below).

The client is primarily intended to be managed in Kubernetes by the [operator](https://github.com/restatedev/restate-operator), but it is possible to run it yourself if necessary.

The tunnel client must be configured with the following values:
- `RESTATE_TUNNEL_NAME`: a name representing the tunnel connection; you might use the name of the cluster in which the client runs.
- `RESTATE_ENVIRONMENT_ID`: the ID of the environment you want to tunnel to
- `RESTATE_SIGNING_PUBLIC_KEY`: the signing public key of your Restate Cloud environment. This allows the client to validate that incoming requests come from your environment.
- `RESTATE_AUTH_TOKEN` (formerly `RESTATE_BEARER_TOKEN`, still accepted): a Restate Cloud API key with the `Full` role.
- `RESTATE_CLOUD_REGION`: The id of the Restate Cloud region in which your environment runs ie `us` or `eu`.

Once running, your Cloud environment can register services at urls like `https://tunnel.$RESTATE_CLOUD_REGION.restate.cloud/$UNPREFIXED_RESTATE_ENVIRONMENT_ID/$RESTATE_TUNNEL_NAME/http/your-service-dns/9080`

For example:
```
restate dep register https://tunnel.us.restate.cloud:9080/201k0yd4rz8yftmd4awh1bajg4v/my-tunnel/http/my-service.my-namespace.svc.cluster.local/9080
```

You only need to build these URLs yourself if you're not using the operator.

## Environment proxy
In addition to exposing local services to Restate Cloud, by default the tunnel client will also serve unauthenticated ingress
and admin endpoints from Restate Cloud on its local 8080 and 9070 ports. This behaviour can be disabled with `RESTATE_ENVIRONMENT_PROXY=false` (`RESTATE_REMOTE_PROXY=false` is still accepted as a deprecated alias). If left enabled, be careful to restrict access to these ports;
access to them is equivalent to having the configured `RESTATE_AUTH_TOKEN`.

Do not set both `RESTATE_ENVIRONMENT_PROXY` and `RESTATE_REMOTE_PROXY`. For rollback compatibility, keep using `RESTATE_REMOTE_PROXY` until every tunnel client binary in the rollout supports `RESTATE_ENVIRONMENT_PROXY`; older binaries ignore the new name and fall back to the default of `true`.

When the tunnel client is managed by the current Restate operator, use `RESTATE_REMOTE_PROXY` for this toggle. The operator emits that env var itself, so adding `RESTATE_ENVIRONMENT_PROXY` separately will make the tunnel client reject the duplicate configuration. Switching the operator to the new name requires a coordinated operator change that never emits both names and only rolls out after the tunnel client image supports `RESTATE_ENVIRONMENT_PROXY`.

## Tuning
`RESTATE_ENVIRONMENT_PROXY_CONNECTIONS` controls the number of outbound HTTP/2 connections to Restate Cloud for each local environment proxy endpoint. The default is `6`, preserving the previous hard-coded value for spreading over cloud load balancer IPs.

`RESTATE_TUNNEL_SERVER_CONNECTIONS` controls how many inbound tunnel connections are opened to each resolved tunnel server. The default is `1`, preserving previous behavior. Total inbound connections are `(resolved tunnel servers) x RESTATE_TUNNEL_SERVER_CONNECTIONS`; raise `RESTATE_POOLS_PER_TUNNEL` as well when a hub needs high fan-out to a single local service.

## Metrics
The health endpoint also serves Prometheus metrics at `/metrics`. Request-level metrics include:

- `restate_cloud_tunnel_requests_total{server,connection,direction,status}` for proxied request throughput.
- `restate_cloud_tunnel_request_duration_seconds{server,connection,direction}` for time from tunnel-client request handling until upstream response headers.
- `restate_cloud_tunnel_requests_inflight{server,connection,direction}` for request concurrency per tunnel or environment-proxy connection.
- `restate_cloud_tunnel_local_handler_duration_seconds{instance}` and `restate_cloud_tunnel_local_handler_inflight{instance}` for local service handler latency and concurrency.

Use `sum without (connection)` to aggregate per-connection tunnel metrics back to the previous per-server view.

## Releasing
1. Update the version in Cargo.{toml,lock} eg to 0.0.2
2. Push a new tag v0.0.2
3. Accept the draft release once the workflow finishes
