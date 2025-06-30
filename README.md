# Restate Cloud Tunnel Client

This repository manages a client intended to establish tunnelling connections from your compute infrastructure
to your Restate Cloud environment, such that your environment can talk to Restate SDK services running in your
private network.

The client is primarily intended to be managed in Kubernetes by the [operator](https://github.com/restatedev/restate-operator), but it is possible to run it yourself if necessary.

The tunnel client must be configured with the following values:
- `RESTATE_TUNNEL_NAME`: a name representing the tunnel connection; you might use the name of the cluster in which the client runs.
- `RESTATE_ENVIRONMENT_ID`: the ID of the environment you want to tunnel to
- `RESTATE_SIGNING_PUBLIC_KEY`: the signing public key of your Restate Cloud environment. This allows the client to validate that incoming requests come from your environment.
- `RESTATE_BEARER_TOKEN`: a Restate Cloud API key with the `Admin` or `Full` role
- `RESTATE_TUNNEL_SERVERS_SRV`: The SRV record for the client to find tunnel servers. This is specific to the region in which your environment runs eg `tunnel.us.restate.cloud`, `tunnel.eu.restate.cloud`.

## Releasing
1. Update the version in Cargo.{toml,lock} eg to 0.0.2
2. Push a new tag v0.0.2
3. Accept the draft release once the workflow finishes
