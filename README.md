# Restate Cloud Tunnel Client

This repository manages a client intended to establish tunnelling connections from your compute infrastructure
to your Restate Cloud environment, such that your environment can talk to Restate SDK services running in your
private network. In addition, the client serves on ports 8080 and 9070, providing unauthenticated access to
your Restate Cloud environment.

The client is primarily intended to be managed in Kubernetes by the [operator](https://github.com/restatedev/restate-operator), but it is possible to run it yourself if necessary.

The tunnel client must be configured with the following values:
- `RESTATE_TUNNEL_NAME`: a name representing the tunnel connection; you might use the name of the cluster in which the client runs.
- `RESTATE_ENVIRONMENT_ID`: the ID of the environment you want to tunnel to
- `RESTATE_SIGNING_PUBLIC_KEY`: the signing public key of your Restate Cloud environment. This allows the client to validate that incoming requests come from your environment.
- `RESTATE_BEARER_TOKEN`: a Restate Cloud API key with the `Full` role.
- `RESTATE_CLOUD_REGION`: The id of the Restate Cloud region in which your environment runs ie `us` or `eu`.

Once running, your Cloud environment can register services at urls like `https://tunnel.$RESTATE_CLOUD_REGION.restate.cloud/$UNPREFIXED_RESTATE_ENVIRONMENT_ID/$RESTATE_TUNNEL_NAME/http/your-service-dns/9080`

For example:
```
restate dep register https://tunnel.us.restate.cloud:9080/201k0yd4rz8yftmd4awh1bajg4v/my-tunnel/http/my-service.my-namespace.svc.cluster.local/9080
```

You only need to build these URLs yourself if you're not using the operator.

## Releasing
1. Update the version in Cargo.{toml,lock} eg to 0.0.2
2. Push a new tag v0.0.2
3. Accept the draft release once the workflow finishes
