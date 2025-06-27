use std::{collections::HashSet, num::NonZeroUsize, path::Path, time::Duration};

use anyhow::bail;
use figment::{
    Figment,
    providers::{Env, Format, Serialized, Toml},
};
use futures::{StreamExt, stream::BoxStream};
use http::Uri;
use restate_types::config::Http2KeepAliveOptions;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

use crate::srv::{HickoryResolver, Resolver, fixed_uri_stream};

#[serde_as]
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
struct OptionsShadow {
    // todo; is it really necessary if we provide a token
    environment_id: Option<String>,
    signing_public_key: Option<String>,
    tunnel_name: Option<String>,
    #[serde_as(as = "Option<HashSet<serde_with::DisplayFromStr>>")]
    tunnel_servers: Option<HashSet<Uri>>,
    #[serde_as(as = "Option<serde_with::DisplayFromStr>")]
    tunnel_servers_srv: Option<hickory_resolver::Name>,
    bearer_token: Option<String>,
    bearer_token_file: Option<String>,
    connect_timeout: Duration,
    pools_per_tunnel: NonZeroUsize,
    initial_max_send_streams: Option<usize>,
    http_keep_alive_options: Http2KeepAliveOptions,
    shutdown_timeout: Duration,
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
        }
    }
}

pub struct Options {
    pub environment_id: String,
    pub signing_public_key: String,
    pub tunnel_name: String,
    pub tunnel_servers: BoxStream<'static, HashSet<Uri>>,
    pub bearer_token: String,
    pub connect_timeout: Duration,
    pub pools_per_tunnel: NonZeroUsize,
    pub initial_max_send_streams: Option<usize>,
    pub http_keep_alive_options: Http2KeepAliveOptions,
    pub shutdown_timeout: Duration,
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
            (None, Some(_)) => todo!(),
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

        let tunnel_servers = match (shadow.tunnel_servers, shadow.tunnel_servers_srv) {
            (None, None) => {
                bail!(
                    "Either 'tunnel_servers' (RESTATE_TUNNEL_SERVERS) or 'tunnel_servers_srv' (RESTATE_TUNNEL_SERVERS_SRV) options must be provided"
                );
            }
            (Some(tunnel_servers), _) => fixed_uri_stream(tunnel_servers).boxed(),
            (None, Some(tunnel_servers_srv)) => {
                let resolver = HickoryResolver::new();

                // check once that it resolves
                resolver.resolve(tunnel_servers_srv.clone()).await?;

                resolver.into_stream(tunnel_servers_srv).boxed()
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
        })
    }
}
