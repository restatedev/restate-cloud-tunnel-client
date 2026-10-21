use std::{
    collections::{HashMap, HashSet},
    net::{Ipv6Addr, SocketAddr, SocketAddrV6},
    num::NonZeroUsize,
    path::{Path, PathBuf},
    str::FromStr,
    time::Duration,
};

use anyhow::{Context, bail};
use figment::{
    Figment, Profile, Provider,
    providers::{Env, Format, Serialized, Toml},
    value::Dict,
};
use futures::{StreamExt, stream::BoxStream};
use http::Uri;
use restate_types::config::Http2KeepAliveOptions;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use tracing::info;

use crate::srv::{HickoryResolver, Resolver, ServerName, fixed_uri_stream};

#[serde_as]
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
struct OptionsShadow {
    environment_id: Option<String>,
    signing_public_key: Option<String>,
    tunnel_name: Option<String>,
    #[serde_as(as = "Option<HashSet<serde_with::DisplayFromStr>>")]
    tunnel_servers: Option<HashSet<Uri>>,
    #[serde_as(as = "Option<serde_with::DisplayFromStr>")]
    tunnel_servers_srv: Option<hickory_resolver::Name>,
    #[serde(alias = "bearer-token", skip_serializing_if = "Option::is_none")]
    auth_token: Option<String>,
    #[serde(alias = "bearer-token-file", skip_serializing_if = "Option::is_none")]
    auth_token_file: Option<PathBuf>,
    connect_timeout: Duration,
    pools_per_tunnel: NonZeroUsize,
    initial_max_send_streams: Option<usize>,
    http_keep_alive_options: Http2KeepAliveOptions,
    shutdown_timeout: Duration,
    health_serve_address: SocketAddr,

    #[serde(skip_serializing_if = "Option::is_none")]
    environment_proxy: Option<bool>,
    environment_proxy_connections: NonZeroUsize,
    tunnel_server_connections: NonZeroUsize,
    ingress_serve_address: SocketAddr,
    admin_serve_address: SocketAddr,

    #[serde_as(as = "serde_with::DisplayFromStr")]
    cloud_suffix: hickory_resolver::Name,
    #[serde_as(as = "Option<serde_with::DisplayFromStr>")]
    cloud_region: Option<hickory_resolver::Name>,
    #[serde_as(as = "Option<serde_with::DisplayFromStr>")]
    ingress_uri: Option<Uri>,
    #[serde_as(as = "Option<serde_with::DisplayFromStr>")]
    admin_uri: Option<Uri>,
}

impl Default for OptionsShadow {
    fn default() -> Self {
        Self {
            environment_id: None,
            signing_public_key: None,
            tunnel_name: None,
            tunnel_servers: None,
            tunnel_servers_srv: None,
            auth_token: None,
            auth_token_file: None,
            connect_timeout: Duration::from_secs(5),
            pools_per_tunnel: NonZeroUsize::new(16).unwrap(),
            initial_max_send_streams: None,
            http_keep_alive_options: Http2KeepAliveOptions::default(),
            shutdown_timeout: Duration::from_secs(300),
            environment_proxy: None,
            // Enough independent connections to spread load across the IPs behind the cloud NLB.
            environment_proxy_connections: NonZeroUsize::new(6).unwrap(),
            tunnel_server_connections: NonZeroUsize::new(1).unwrap(),
            health_serve_address: SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::UNSPECIFIED,
                9090,
                0,
                0,
            )),
            ingress_serve_address: SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::UNSPECIFIED,
                8080,
                0,
                0,
            )),
            admin_serve_address: SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::UNSPECIFIED,
                9070,
                0,
                0,
            )),
            cloud_suffix: hickory_resolver::Name::from_str("restate.cloud.")
                .expect("restate.cloud is a valid domain"),
            cloud_region: None,
            ingress_uri: None,
            admin_uri: None,
        }
    }
}

const ENVIRONMENT_PROXY_KEY: &str = "environment-proxy";
/// Deprecated alias for `environment-proxy`.
const REMOTE_PROXY_KEY: &str = "remote-proxy";

/// Reads the config file, renaming the deprecated `remote-proxy` key to `environment-proxy`
/// so that the name a layer uses does not affect precedence between layers. Setting both
/// names in the same file is ambiguous and rejected.
fn config_file_layer(path: &Path) -> anyhow::Result<Dict> {
    let mut layers = Toml::file(path).data()?;
    let mut file = layers.remove(&Profile::Default).unwrap_or_default();

    if let Some(remote_proxy) = file.remove(REMOTE_PROXY_KEY) {
        if file.contains_key(ENVIRONMENT_PROXY_KEY) {
            bail!(
                "Both '{ENVIRONMENT_PROXY_KEY}' and '{REMOTE_PROXY_KEY}' are set in {}; unset '{REMOTE_PROXY_KEY}' (deprecated alias for '{ENVIRONMENT_PROXY_KEY}')",
                path.display()
            );
        }
        file.insert(ENVIRONMENT_PROXY_KEY.to_owned(), remote_proxy);
    }

    Ok(file)
}

/// `RESTATE_*` variables as config keys, with `RESTATE_REMOTE_PROXY` mapped onto
/// `environment-proxy`. Setting both variables is rejected by `Options::load`.
fn environment_layer() -> Env {
    Env::prefixed("RESTATE_").split("__").map(|key| {
        let key = key.as_str().to_ascii_lowercase().replace('_', "-");
        if key == REMOTE_PROXY_KEY {
            ENVIRONMENT_PROXY_KEY.into()
        } else {
            key.into()
        }
    })
}

pub struct Options {
    pub environment_id: String,
    pub signing_public_key: String,
    pub auth_token: String,

    pub tunnel_name: String,
    pub tunnel_servers: BoxStream<'static, HashMap<Uri, ServerName>>,

    pub connect_timeout: Duration,
    pub pools_per_tunnel: NonZeroUsize,
    pub initial_max_send_streams: Option<usize>,
    pub http_keep_alive_options: Http2KeepAliveOptions,
    pub shutdown_timeout: Duration,
    pub health_serve_address: SocketAddr,

    pub environment_proxy: bool,
    pub environment_proxy_connections: NonZeroUsize,
    pub tunnel_server_connections: NonZeroUsize,

    pub ingress_serve_address: SocketAddr,
    pub ingress_uri: Uri,

    pub admin_serve_address: SocketAddr,
    pub admin_uri: Uri,
}

impl Options {
    pub async fn load(path: &Path) -> anyhow::Result<Options> {
        let defaults = OptionsShadow::default();
        let mut figment = Figment::from(Serialized::defaults(defaults));
        figment = figment.merge(Serialized::defaults(config_file_layer(path)?));

        if std::env::var_os("RESTATE_AUTH_TOKEN").is_some()
            && std::env::var_os("RESTATE_BEARER_TOKEN").is_some()
        {
            bail!(
                "Both RESTATE_AUTH_TOKEN and RESTATE_BEARER_TOKEN are set; unset RESTATE_BEARER_TOKEN (deprecated alias for RESTATE_AUTH_TOKEN)"
            );
        }
        if std::env::var_os("RESTATE_AUTH_TOKEN_FILE").is_some()
            && std::env::var_os("RESTATE_BEARER_TOKEN_FILE").is_some()
        {
            bail!(
                "Both RESTATE_AUTH_TOKEN_FILE and RESTATE_BEARER_TOKEN_FILE are set; unset RESTATE_BEARER_TOKEN_FILE (deprecated alias for RESTATE_AUTH_TOKEN_FILE)"
            );
        }
        if std::env::var_os("RESTATE_ENVIRONMENT_PROXY").is_some()
            && std::env::var_os("RESTATE_REMOTE_PROXY").is_some()
        {
            bail!(
                "Both RESTATE_ENVIRONMENT_PROXY and RESTATE_REMOTE_PROXY are set; unset RESTATE_REMOTE_PROXY (deprecated alias for RESTATE_ENVIRONMENT_PROXY)"
            );
        }

        figment = figment.merge(environment_layer());

        let shadow: OptionsShadow = figment.extract()?;

        let auth_token = match (shadow.auth_token, shadow.auth_token_file) {
            (None, None) => {
                bail!(
                    "Either 'auth_token' (RESTATE_AUTH_TOKEN) or 'auth_token_file' (RESTATE_AUTH_TOKEN_FILE) options must be provided"
                );
            }
            (Some(auth_token), _) => auth_token,
            (None, Some(auth_token_file)) => {
                let mut auth_token = tokio::fs::read_to_string(&auth_token_file)
                    .await
                    .context("failed to read auth token file")?;
                auth_token.truncate(auth_token.trim_end().len());
                info!(
                    "Loaded initial auth token from {}",
                    auth_token_file.display()
                );
                auth_token
            }
        };

        let Some(environment_id) = shadow.environment_id else {
            bail!("The option 'environment_id' (RESTATE_ENVIRONMENT_ID) must be provided");
        };

        let Some(signing_public_key) = shadow.signing_public_key else {
            bail!("The option 'signing_public_key' (RESTATE_SIGNING_PUBLIC_KEY) must be provided");
        };

        let Some(tunnel_name) = shadow.tunnel_name else {
            bail!("The option 'tunnel_name' (RESTATE_TUNNEL_NAME) must be provided");
        };

        let tunnel_servers = match (
            shadow.tunnel_servers,
            shadow.tunnel_servers_srv,
            &shadow.cloud_region,
        ) {
            (None, None, None) => {
                bail!(
                    "Either 'tunnel_servers' (RESTATE_TUNNEL_SERVERS), 'tunnel_servers_srv' (RESTATE_TUNNEL_SERVERS_SRV) or 'cloud_region' (RESTATE_CLOUD_REGION) options must be provided"
                );
            }
            (Some(tunnel_servers), _, _) => {
                let tunnel_servers = tunnel_servers
                    .into_iter()
                    .map(|tunnel_server| {
                        let host = tunnel_server
                            .host()
                            .context("tunnel_servers must have a host")?;
                        let server_name = ServerName::from_str(host)
                            .context("tunnel_servers hosts must be valid tls server names")?;
                        Result::<_, anyhow::Error>::Ok((tunnel_server, server_name))
                    })
                    .collect::<Result<HashMap<_, _>, _>>()?;
                fixed_uri_stream(tunnel_servers).boxed()
            }
            (None, Some(tunnel_servers_srv), _) => {
                let resolver = HickoryResolver::new();

                // check once that it resolves
                resolver.resolve_srv(tunnel_servers_srv.clone()).await?;

                resolver.into_stream(tunnel_servers_srv).boxed()
            }
            (None, None, Some(cloud_region)) => {
                let resolver = HickoryResolver::new();

                let mut tunnel_servers_srv = shadow.cloud_suffix.clone();
                for region_part in cloud_region.iter().rev() {
                    tunnel_servers_srv = tunnel_servers_srv.prepend_label(region_part)?;
                }
                tunnel_servers_srv = tunnel_servers_srv.prepend_label("tunnel")?;

                // check once that it resolves
                resolver.resolve_srv(tunnel_servers_srv.clone()).await?;

                resolver.into_stream(tunnel_servers_srv).boxed()
            }
        };

        let ingress_uri = match (shadow.ingress_uri, &shadow.cloud_region) {
            (None, None) => {
                bail!(
                    "Either 'ingress_uri' (RESTATE_INGRESS_URI), or 'cloud_region' (RESTATE_CLOUD_REGION) options must be provided"
                );
            }
            (Some(ingress_uri), _) => ingress_uri,
            (None, Some(cloud_region)) => {
                let unprefixed_environment_id = environment_id
                    .strip_prefix("env_")
                    .unwrap_or(&environment_id);
                let mut ingress_name = shadow.cloud_suffix.clone();
                for region_part in cloud_region.iter().rev() {
                    ingress_name = ingress_name.prepend_label(region_part)?;
                }
                ingress_name = ingress_name
                    .prepend_label("env")?
                    .prepend_label(unprefixed_environment_id)?;

                Uri::from_str(&format!("https://{ingress_name}:8080"))?
            }
        };

        let admin_uri = match (shadow.admin_uri, &shadow.cloud_region) {
            (None, None) => {
                bail!(
                    "Either 'admin_uri' (RESTATE_ADMIN_URI), or 'cloud_region' (RESTATE_CLOUD_REGION) options must be provided"
                );
            }
            (Some(admin_uri), _) => admin_uri,
            (None, Some(cloud_region)) => {
                let unprefixed_environment_id = environment_id
                    .strip_prefix("env_")
                    .unwrap_or(&environment_id);
                let mut admin_name = shadow.cloud_suffix.clone();
                for region_part in cloud_region.iter().rev() {
                    admin_name = admin_name.prepend_label(region_part)?;
                }
                admin_name = admin_name
                    .prepend_label("env")?
                    .prepend_label(unprefixed_environment_id)?;

                Uri::from_str(&format!("https://{admin_name}:9070"))?
            }
        };

        Ok(Options {
            environment_id,
            signing_public_key,
            tunnel_name,
            tunnel_servers,
            auth_token,
            connect_timeout: shadow.connect_timeout,
            pools_per_tunnel: shadow.pools_per_tunnel,
            initial_max_send_streams: shadow.initial_max_send_streams,
            http_keep_alive_options: shadow.http_keep_alive_options,
            shutdown_timeout: shadow.shutdown_timeout,
            health_serve_address: shadow.health_serve_address,
            environment_proxy: shadow.environment_proxy.unwrap_or(true),
            environment_proxy_connections: shadow.environment_proxy_connections,
            tunnel_server_connections: shadow.tunnel_server_connections,
            ingress_serve_address: shadow.ingress_serve_address,
            ingress_uri,
            admin_serve_address: shadow.admin_serve_address,
            admin_uri,
        })
    }
}

#[cfg(test)]
mod tests {
    use figment::Jail;

    use super::*;

    const REQUIRED_TOML: &str = r#"
environment-id = "env_test"
signing-public-key = "test-signing-public-key"
tunnel-name = "test-tunnel"
tunnel-servers = ["https://127.0.0.1:19080/"]
auth-token = "test-auth-token"
ingress-uri = "https://ingress.example.com:8080/"
admin-uri = "https://admin.example.com:9070/"
"#;

    /// Runs `body` with an empty environment and a temporary working directory that holds a
    /// `tunnel.toml` made of the required options plus `extra_toml`.
    fn with_config(extra_toml: &str, body: impl FnOnce(&mut Jail) -> figment::error::Result<()>) {
        Jail::expect_with(|jail| {
            jail.clear_env();
            jail.create_file("tunnel.toml", &format!("{REQUIRED_TOML}{extra_toml}"))?;
            body(jail)
        });
    }

    fn load_options() -> anyhow::Result<Options> {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(Options::load(Path::new("tunnel.toml")))
    }

    fn load_error() -> String {
        match load_options() {
            Ok(_) => panic!("expected Options::load to fail"),
            Err(error) => error.to_string(),
        }
    }

    #[test]
    fn defaults_connection_tuning_knobs() {
        with_config("", |_| {
            let options = load_options().unwrap();

            assert!(options.environment_proxy);
            assert_eq!(options.environment_proxy_connections.get(), 6);
            assert_eq!(options.tunnel_server_connections.get(), 1);
            Ok(())
        });
    }

    #[test]
    fn env_overrides_connection_tuning_knobs() {
        with_config("", |jail| {
            jail.set_env("RESTATE_ENVIRONMENT_PROXY", "false");
            jail.set_env("RESTATE_ENVIRONMENT_PROXY_CONNECTIONS", "9");
            jail.set_env("RESTATE_TUNNEL_SERVER_CONNECTIONS", "3");

            let options = load_options().unwrap();

            assert!(!options.environment_proxy);
            assert_eq!(options.environment_proxy_connections.get(), 9);
            assert_eq!(options.tunnel_server_connections.get(), 3);
            Ok(())
        });
    }

    #[test]
    fn remote_proxy_env_alias_sets_environment_proxy() {
        with_config("", |jail| {
            jail.set_env("RESTATE_REMOTE_PROXY", "false");

            assert!(!load_options().unwrap().environment_proxy);
            Ok(())
        });
    }

    #[test]
    fn remote_proxy_file_alias_sets_environment_proxy() {
        with_config("remote-proxy = false", |_| {
            assert!(!load_options().unwrap().environment_proxy);
            Ok(())
        });
    }

    #[test]
    fn env_remote_proxy_overrides_file_environment_proxy() {
        with_config("environment-proxy = true", |jail| {
            jail.set_env("RESTATE_REMOTE_PROXY", "false");

            assert!(!load_options().unwrap().environment_proxy);
            Ok(())
        });
    }

    #[test]
    fn env_environment_proxy_overrides_file_remote_proxy() {
        with_config("remote-proxy = true", |jail| {
            jail.set_env("RESTATE_ENVIRONMENT_PROXY", "false");

            assert!(!load_options().unwrap().environment_proxy);
            Ok(())
        });
    }

    #[test]
    fn both_proxy_names_in_file_fail_with_helpful_error() {
        with_config("environment-proxy = true\nremote-proxy = false", |_| {
            assert!(
                load_error().contains("Both 'environment-proxy' and 'remote-proxy' are set in")
            );
            Ok(())
        });
    }

    #[test]
    fn both_proxy_names_in_env_fail_with_helpful_error() {
        with_config("", |jail| {
            jail.set_env("RESTATE_ENVIRONMENT_PROXY", "true");
            jail.set_env("RESTATE_REMOTE_PROXY", "false");

            assert!(
                load_error()
                    .contains("Both RESTATE_ENVIRONMENT_PROXY and RESTATE_REMOTE_PROXY are set")
            );
            Ok(())
        });
    }

    #[test]
    fn shadow_defaults_do_not_serialize_environment_proxy() {
        Jail::expect_with(|jail| {
            jail.clear_env();
            let shadow: OptionsShadow =
                Figment::from(Serialized::defaults(OptionsShadow::default()))
                    .merge(environment_layer())
                    .extract()
                    .unwrap();

            assert_eq!(shadow.environment_proxy, None);
            Ok(())
        });
    }
}
