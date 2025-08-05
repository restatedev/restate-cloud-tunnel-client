use std::{
    collections::HashSet,
    net::{SocketAddr, SocketAddrV4},
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
use url::Url;

use crate::srv::{HickoryResolver, Resolver, fixed_uri_stream};

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
    bearer_token: Option<String>,
    bearer_token_file: Option<PathBuf>,
    connect_timeout: Duration,
    pools_per_tunnel: NonZeroUsize,
    initial_max_send_streams: Option<usize>,
    http_keep_alive_options: Http2KeepAliveOptions,
    shutdown_timeout: Duration,
    health_serve_address: SocketAddr,
    ingress_serve_address: SocketAddr,
    admin_serve_address: SocketAddr,
    #[serde_as(as = "serde_with::DisplayFromStr")]
    cloud_suffix: hickory_resolver::Name,
    cloud_region: Option<String>,
    #[serde_as(as = "Option<serde_with::DisplayFromStr>")]
    ingress_url: Option<Url>,
    #[serde_as(as = "Option<serde_with::DisplayFromStr>")]
    admin_url: Option<Url>,
}

impl Default for OptionsShadow {
    fn default() -> Self {
        Self {
            environment_id: None,
            signing_public_key: None,
            tunnel_name: None,
            tunnel_servers: None,
            tunnel_servers_srv: None,
            bearer_token: None,
            bearer_token_file: None,
            connect_timeout: Duration::from_secs(5),
            pools_per_tunnel: NonZeroUsize::new(16).unwrap(),
            initial_max_send_streams: None,
            http_keep_alive_options: Http2KeepAliveOptions::default(),
            shutdown_timeout: Duration::from_secs(300),
            health_serve_address: SocketAddr::V4(SocketAddrV4::new([0, 0, 0, 0].into(), 9090)),
            ingress_serve_address: SocketAddr::V4(SocketAddrV4::new([0, 0, 0, 0].into(), 8080)),
            admin_serve_address: SocketAddr::V4(SocketAddrV4::new([0, 0, 0, 0].into(), 9070)),
            cloud_suffix: hickory_resolver::Name::from_str("restate.cloud")
                .expect("restate.cloud is a valid domain"),
            cloud_region: None,
            ingress_url: None,
            admin_url: None,
        }
    }
}

pub struct Options {
    pub environment_id: String,
    pub signing_public_key: String,
    pub bearer_token: String,

    pub tunnel_name: String,
    pub tunnel_servers: BoxStream<'static, HashSet<Uri>>,

    pub connect_timeout: Duration,
    pub pools_per_tunnel: NonZeroUsize,
    pub initial_max_send_streams: Option<usize>,
    pub http_keep_alive_options: Http2KeepAliveOptions,
    pub shutdown_timeout: Duration,
    pub health_serve_address: SocketAddr,

    pub ingress_serve_address: SocketAddr,
    pub ingress_url: Url,

    pub admin_serve_address: SocketAddr,
    pub admin_url: Url,
}

impl Options {
    pub async fn load(path: &Path) -> anyhow::Result<Options> {
        let defaults = OptionsShadow::default();
        let mut figment = Figment::from(Serialized::defaults(defaults));
        // Load configuration file
        figment = figment.merge(Toml::file(path));

        figment = figment.merge(
            Env::prefixed("RESTATE_")
                .split("__")
                .map(|k| k.as_str().replace('_', "-").into()),
        );

        let shadow: OptionsShadow = figment.extract()?;

        let bearer_token = match (shadow.bearer_token, shadow.bearer_token_file) {
            (None, None) => {
                bail!(
                    "Either 'bearer_token' (RESTATE_BEARER_TOKEN) or 'bearer_token_file' (RESTATE_BEARER_TOKEN_FILE) options must be provided"
                );
            }
            (Some(bearer_token), _) => bearer_token,
            (None, Some(bearer_token_file)) => {
                let mut bearer_token = tokio::fs::read_to_string(&bearer_token_file)
                    .await
                    .context("failed to read bearer token file")?;
                bearer_token.truncate(bearer_token.trim_end().len());
                info!(
                    "Loaded initial bearer token from {}",
                    bearer_token_file.display()
                );
                bearer_token
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
            (Some(tunnel_servers), _, _) => fixed_uri_stream(tunnel_servers).boxed(),
            (None, Some(tunnel_servers_srv), _) => {
                let resolver = HickoryResolver::new();

                // check once that it resolves
                resolver.resolve(tunnel_servers_srv.clone()).await?;

                resolver.into_stream(tunnel_servers_srv).boxed()
            }
            (None, None, Some(cloud_region)) => {
                let resolver = HickoryResolver::new();

                let tunnel_servers_srv = shadow
                    .cloud_suffix
                    .prepend_label(cloud_region.clone())?
                    .prepend_label("tunnel")?;

                // check once that it resolves
                resolver.resolve(tunnel_servers_srv.clone()).await?;

                resolver.into_stream(tunnel_servers_srv).boxed()
            }
        };

        let ingress_url = match (shadow.ingress_url, &shadow.cloud_region) {
            (None, None) => {
                bail!(
                    "Either 'ingress_url' (RESTATE_INGRESS_URL), or 'cloud_suffix' (RESTATE_CLOUD_SUFFIX) options must be provided"
                );
            }
            (Some(ingress_url), _) => ingress_url,
            (None, Some(cloud_region)) => {
                let unprefixed_environment_id = environment_id
                    .strip_prefix("env_")
                    .unwrap_or(&environment_id);
                let ingress_name = shadow
                    .cloud_suffix
                    .prepend_label(cloud_region.clone())?
                    .prepend_label("env")?
                    .prepend_label(unprefixed_environment_id)?;

                Url::from_str(&format!("https://{ingress_name}:8080"))
                    .context("Invalid cloud_suffix")?
            }
        };

        let admin_url = match (shadow.admin_url, &shadow.cloud_region) {
            (None, None) => {
                bail!(
                    "Either 'admin_url' (RESTATE_ADMIN_URL), or 'cloud_suffix' (RESTATE_CLOUD_SUFFIX) options must be provided"
                );
            }
            (Some(admin_url), _) => admin_url,
            (None, Some(cloud_region)) => {
                let unprefixed_environment_id = environment_id
                    .strip_prefix("env_")
                    .unwrap_or(&environment_id);
                let admin_name = shadow
                    .cloud_suffix
                    .prepend_label(cloud_region.clone())?
                    .prepend_label("env")?
                    .prepend_label(unprefixed_environment_id)?;

                Url::from_str(&format!("https://{admin_name}:9070"))
                    .context("Invalid cloud_suffix")?
            }
        };

        Ok(Options {
            environment_id,
            signing_public_key,
            tunnel_name,
            tunnel_servers,
            bearer_token,
            connect_timeout: shadow.connect_timeout,
            pools_per_tunnel: shadow.pools_per_tunnel,
            initial_max_send_streams: shadow.initial_max_send_streams,
            http_keep_alive_options: shadow.http_keep_alive_options,
            shutdown_timeout: shadow.shutdown_timeout,
            health_serve_address: shadow.health_serve_address,
            ingress_serve_address: shadow.ingress_serve_address,
            ingress_url,
            admin_serve_address: shadow.admin_serve_address,
            admin_url,
        })
    }
}
