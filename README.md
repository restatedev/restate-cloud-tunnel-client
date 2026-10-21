# Restate Cloud Tunnel Client

This repository manages a client intended to establish tunnelling connections from your compute infrastructure
to your Restate Cloud environment, such that your environment can talk to Restate SDK services running in your
private network. In addition, the client can serve on ports 8080 and 9070, providing unauthenticated access to
your Restate Cloud environment (see 'Remote proxy' below).

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

## Remote proxy
In addition to exposing local services to Restate Cloud, by default the tunnel client will also serve unauthenticated ingress
and admin endpoints from Restate Cloud on its local 8080 and 9080 ports. This behaviour can be disabled with `RESTATE_REMOTE_PROXY=false`. If left enabled, be careful to restrict access to these ports;
access to them is equivalent to having the configured `RESTATE_AUTH_TOKEN`.

## GCP auth
By default, requests from Restate Cloud are forwarded to your services with their headers unchanged, and
your services verify the request signature to check that requests come from your environment. If your
services run on Cloud Run with invoker IAM enforced, set `RESTATE_GCP_AUTH=true` to have the client attach
`Authorization: Bearer <Google ID token>` to every request proxied to an `https` destination. The token is
minted by the GCE / Cloud Run metadata server for the service account the client runs as, with audience
`https://<destination host>`; grant that service account `roles/run.invoker` on the destination services.
Tokens are cached per audience and refreshed every 50 minutes.

If a token cannot be obtained the request is answered with `502` and
`restate_cloud_tunnel_gcp_auth_failures_total` is incremented. Any `Authorization` header already present on
the request is replaced. Cleartext (`http`) destinations are always proxied unchanged. `GCE_METADATA_HOST`
overrides the metadata server host, e.g. for testing outside Google Cloud.

## Releasing
1. Update the version in Cargo.{toml,lock} eg to 0.0.2
2. Push a new tag v0.0.2
3. Accept the draft release once the workflow finishes
