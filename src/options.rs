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
    Figment,
    providers::{Env, Format, Serialized, Toml},
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

    #[serde(alias = "remote-proxy", skip_serializing_if = "Option::is_none")]
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
            // Preserve the previous hard-coded fan-out for spreading over cloud NLB IPs.
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
        // Load configuration file
        figment = figment.merge(Toml::file(path));

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

        figment = figment.merge(
            Env::prefixed("RESTATE_")
                .split("__")
                .map(|k| k.as_str().replace('_', "-").into()),
        );

        if figment.contains("environment-proxy") && figment.contains("remote-proxy") {
            bail!(
                "Both 'environment-proxy' and 'remote-proxy' are set; unset 'remote-proxy' (deprecated alias for 'environment-proxy')"
            );
        }

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
    use std::{
        env,
        ffi::OsString,
        sync::{Mutex, MutexGuard},
    };

    use super::*;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    const TEST_ENV_KEYS: &[&str] = &[
        "RESTATE_ADMIN_URI",
        "RESTATE_AUTH_TOKEN",
        "RESTATE_AUTH_TOKEN_FILE",
        "RESTATE_BEARER_TOKEN",
        "RESTATE_BEARER_TOKEN_FILE",
        "RESTATE_CLOUD_REGION",
        "RESTATE_ENVIRONMENT_PROXY",
        "RESTATE_ENVIRONMENT_PROXY_CONNECTIONS",
        "RESTATE_INGRESS_URI",
        "RESTATE_REMOTE_PROXY",
        "RESTATE_SIGNING_PUBLIC_KEY",
        "RESTATE_TUNNEL_NAME",
        "RESTATE_TUNNEL_SERVERS",
        "RESTATE_TUNNEL_SERVERS_SRV",
        "RESTATE_TUNNEL_SERVER_CONNECTIONS",
    ];

    struct EnvGuard {
        saved: Vec<(&'static str, Option<OsString>)>,
        _lock: MutexGuard<'static, ()>,
    }

    impl EnvGuard {
        fn new() -> Self {
            let lock = ENV_LOCK
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let saved = TEST_ENV_KEYS
                .iter()
                .map(|key| (*key, env::var_os(key)))
                .collect();

            for key in TEST_ENV_KEYS {
                unsafe {
                    env::remove_var(key);
                }
            }

            Self { saved, _lock: lock }
        }

        fn set(&self, key: &str, value: &str) {
            unsafe {
                env::set_var(key, value);
            }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            for (key, value) in &self.saved {
                unsafe {
                    if let Some(value) = value {
                        env::set_var(key, value);
                    } else {
                        env::remove_var(key);
                    }
                }
            }
        }
    }

    fn load_options_from_toml_with_extra(extra_toml: &str) -> anyhow::Result<Options> {
        let path = env::temp_dir().join(format!(
            "restate-cloud-tunnel-client-options-{}.toml",
            std::process::id()
        ));

        std::fs::write(
            &path,
            format!(
                r#"
environment-id = "env_test"
signing-public-key = "test-signing-public-key"
tunnel-name = "test-tunnel"
tunnel-servers = ["https://127.0.0.1:19080/"]
auth-token = "test-auth-token"
ingress-uri = "https://ingress.example.com:8080/"
admin-uri = "https://admin.example.com:9070/"
{extra_toml}
"#,
            ),
        )
        .unwrap();

        let options = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(Options::load(&path));

        let _ = std::fs::remove_file(path);

        options
    }

    fn load_options_from_toml() -> Options {
        load_options_from_toml_with_extra("").unwrap()
    }

    fn extract_shadow_from_env() -> OptionsShadow {
        Figment::from(Serialized::defaults(OptionsShadow::default()))
            .merge(
                Env::prefixed("RESTATE_")
                    .split("__")
                    .map(|k| k.as_str().replace('_', "-").into()),
            )
            .extract()
            .unwrap()
    }

    #[test]
    fn defaults_connection_tuning_knobs() {
        let _env_guard = EnvGuard::new();
        let defaults = load_options_from_toml();

        assert!(defaults.environment_proxy);
        assert_eq!(defaults.environment_proxy_connections.get(), 6);
        assert_eq!(defaults.tunnel_server_connections.get(), 1);
    }

    #[test]
    fn env_overrides_connection_tuning_knobs() {
        let env_guard = EnvGuard::new();
        env_guard.set("RESTATE_ENVIRONMENT_PROXY", "false");
        env_guard.set("RESTATE_ENVIRONMENT_PROXY_CONNECTIONS", "9");
        env_guard.set("RESTATE_TUNNEL_SERVER_CONNECTIONS", "3");

        let options = load_options_from_toml();

        assert!(!options.environment_proxy);
        assert_eq!(options.environment_proxy_connections.get(), 9);
        assert_eq!(options.tunnel_server_connections.get(), 3);
    }

    #[test]
    fn remote_proxy_env_alias_loads_without_collision() {
        let env_guard = EnvGuard::new();
        env_guard.set("RESTATE_REMOTE_PROXY", "false");

        let options = load_options_from_toml();

        assert!(!options.environment_proxy);
    }

    #[test]
    fn environment_proxy_env_sets_environment_proxy() {
        let env_guard = EnvGuard::new();
        env_guard.set("RESTATE_ENVIRONMENT_PROXY", "false");

        let options = load_options_from_toml();

        assert!(!options.environment_proxy);
    }

    #[test]
    fn environment_proxy_and_remote_proxy_envs_fail_with_helpful_error() {
        let env_guard = EnvGuard::new();
        env_guard.set("RESTATE_ENVIRONMENT_PROXY", "true");
        env_guard.set("RESTATE_REMOTE_PROXY", "false");

        let error = match load_options_from_toml_with_extra("") {
            Ok(_) => panic!("expected environment proxy aliases to fail"),
            Err(error) => error,
        };

        assert!(
            error
                .to_string()
                .contains("Both RESTATE_ENVIRONMENT_PROXY and RESTATE_REMOTE_PROXY are set")
        );
    }

    #[test]
    fn environment_proxy_and_remote_proxy_sources_fail_with_helpful_error() {
        let env_guard = EnvGuard::new();
        env_guard.set("RESTATE_ENVIRONMENT_PROXY", "true");

        let error = match load_options_from_toml_with_extra("remote-proxy = false") {
            Ok(_) => panic!("expected environment proxy aliases to fail"),
            Err(error) => error,
        };

        assert!(
            error
                .to_string()
                .contains("Both 'environment-proxy' and 'remote-proxy' are set")
        );
    }

    #[test]
    fn shadow_defaults_do_not_serialize_environment_proxy() {
        let _env_guard = EnvGuard::new();
        let shadow = extract_shadow_from_env();

        assert_eq!(shadow.environment_proxy, None);
    }
}
