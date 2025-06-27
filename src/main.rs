use std::{
    collections::HashMap,
    fmt::Display,
    path::PathBuf,
    str::FromStr,
    sync::atomic::{AtomicUsize, Ordering},
    time::Duration,
};

use bytes::Bytes;
use clap::Parser;
use futures::StreamExt;
use http::{Request, Response, StatusCode, Uri};
use hyper::body::Incoming;
use hyper_rustls::HttpsConnector;
use hyper_util::client::legacy::connect::HttpConnector;
use restate_cloud_tunnel_client::client::{
    Handler, HandlerNotification, ServeError, TLS_CLIENT_CONFIG,
};
use restate_types::retries::RetryPolicy;
use tokio::time::Instant;
use tokio_util::{sync::CancellationToken, task::TaskTracker};
use tracing::{Instrument, debug, error, info, info_span, warn};
use tracing_subscriber::filter::LevelFilter;

use crate::{options::Options, signal::shutdown};

mod options;
mod signal;
mod srv;

#[derive(Debug, clap::Parser)]
struct Arguments {
    #[arg(
        short,
        long = "config-file",
        env = "CONFIG",
        default_value = "tunnel.yaml",
        value_name = "FILE"
    )]
    config_file: PathBuf,
}

#[tokio::main(flavor = "multi_thread")]
pub async fn main() -> anyhow::Result<()> {
    let format = tracing_subscriber::fmt::format().json();

    let args: Arguments = Arguments::parse();

    let mut options = Options::load(args.config_file.as_path()).await?;

    tracing_subscriber::fmt()
        .event_format(format)
        .fmt_fields(tracing_subscriber::fmt::format::JsonFields::new())
        .with_env_filter(
            tracing_subscriber::EnvFilter::builder()
                .with_default_directive(LevelFilter::INFO.into())
                .from_env_lossy(),
        )
        .init();

    let mut builder =
        hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::default());
    builder.timer(hyper_util::rt::TokioTimer::default());

    builder
        // todo; we can later have separate h2c and http1.1 clients and switch between them based on either a header or some host regex
        .http2_only(true)
        .http2_initial_max_send_streams(options.initial_max_send_streams)
        .http2_adaptive_window(true)
        .http2_keep_alive_timeout(options.http_keep_alive_options.timeout.into())
        .http2_keep_alive_interval(Some(options.http_keep_alive_options.interval.into()));

    let mut http_connector = HttpConnector::new();
    http_connector.enforce_http(false);
    http_connector.set_nodelay(true);
    http_connector.set_connect_timeout(Some(options.connect_timeout));

    let https_connector = hyper_rustls::HttpsConnectorBuilder::new()
        .with_tls_config(TLS_CLIENT_CONFIG.clone())
        .https_or_http()
        .enable_http1()
        .enable_http2()
        .wrap_connector(http_connector.clone());

    let mut uris = HashMap::new();
    let connections = TaskTracker::new();
    let token = CancellationToken::new();
    let mut shutdown_fut = std::pin::pin!(shutdown());

    loop {
        let tunnel_servers = tokio::select! {
            _ = &mut shutdown_fut => {
                break
            }
            tunnel_servers = options.tunnel_servers.next() => {
                match tunnel_servers {
                    Some(tunnel_servers) => tunnel_servers,
                    None => break,
                }
            }
        };

        for server in &tunnel_servers {
            if uris.contains_key(server) {
                continue;
            }

            info!(%server, "Starting new tunnel");

            let token = token.child_token();

            let client = round_robin_client(&options, &builder, &https_connector);

            let handler = Handler::<(), ()>::new(
                hyper::service::service_fn(move |req| do_proxy(client.get().clone(), req)),
                options.connect_timeout,
                &options.environment_id,
                &options.signing_public_key,
                &options.bearer_token,
                Some(options.tunnel_name.clone()),
                Option::<fn(_)>::None,
            )
            .expect("failed to create tunnel handler");

            let fut = handle_tunnel_uri(handler, token.clone(), server.clone())
                .instrument(info_span!("tunnel", server = %server).or_current());

            tokio::spawn(connections.track_future(fut));
            uris.insert(server.clone(), token);
        }

        uris.retain(|existing_uri, token| {
            if !tunnel_servers.contains(existing_uri) {
                info!(server = %existing_uri, "Tearing down tunnel");

                token.cancel();
                false
            } else {
                true
            }
        });
    }

    token.cancel();
    connections.close();

    let shutdown_result = tokio::time::timeout(options.shutdown_timeout, connections.wait()).await;

    if shutdown_result.is_err() {
        warn!("Could not gracefully shut down, terminating now.");
    } else {
        info!("Tunnels have been gracefully shut down.");
    }

    Ok(())
}

async fn handle_tunnel_uri<Notify, Client, ClientError, ClientFuture, ResponseBody>(
    handler: Handler<Notify, Client>,
    token: CancellationToken,
    server: Uri,
) where
    Notify: Fn(HandlerNotification) + Send + Sync + 'static,
    Client: hyper::service::Service<
            Request<Incoming>,
            Error = ClientError,
            Future = ClientFuture,
            Response = Response<ResponseBody>,
        > + Send
        + Sync
        + 'static,
    ClientError: std::fmt::Display + Send + Sync + 'static,
    ClientFuture:
        Future<Output = Result<Response<ResponseBody>, ClientError>> + Send + Sync + 'static,
    ResponseBody: hyper::body::Body<Data = bytes::Bytes> + Send + Sync + 'static,
    ResponseBody::Error:
        Display + Into<Box<dyn std::error::Error + Send + Sync + 'static>> + Send + Sync + 'static,
{
    let retry_policy = RetryPolicy::exponential(
        Duration::from_millis(10),
        2.0,
        None,
        Some(Duration::from_secs(120)),
    );

    let mut retry_iter = retry_policy.clone().into_iter();

    loop {
        let handler = handler.clone();
        let server = server.clone();
        let on_drain = CancellationToken::new();

        info!("Establishing tunnel connection");
        let mut handle = tokio::spawn(handler.serve(server, token.child_token(), on_drain.clone()));
        let start = Instant::now();

        tokio::select! {
            err = &mut handle => {
                // conn exited; start a new one
                match err {
                    Ok(ServeError::ClientClosed(status)) => {
                        debug!("Closed tunnel connection while in status {status}");
                    }
                    Ok(err) => {
                        error!("Tunnel failed: {err}");
                    }
                    Err(join_err) => {
                        // likely panic
                        error!("Tunnel exited unexpectedly: {join_err}");
                    }
                }
            }
            _ = on_drain.cancelled() => {
                tokio::task::spawn(async move {
                    match tokio::time::timeout(Duration::from_secs(120), &mut handle).await {
                        Ok(Ok(ServeError::ClientClosed(status))) => {
                            debug!("Closed tunnel connection while in status {status}");
                        }
                        Ok(Ok(ServeError::ServerClosed(_))) => {
                            debug!("Server closed tunnel connection after drain notification");
                        }
                        Ok(Ok(err)) => {
                            error!("Tunnel failed: {err}");
                        }
                        Ok(Err(join_err)) => {
                            // likely panic
                            error!("Tunnel exited unexpectedly: {join_err}");
                        }
                        Err(_timeout) => {
                            handle.abort();
                            warn!("Server sent a drain notification but the tunnel did not exit in time");
                        }
                    }
                }.in_current_span());
                info!("Server requested drain; starting new tunnel connection")
            }
        }

        if start.elapsed() > Duration::from_secs(30) {
            // if the tunnel ran for a reasonable amount of time, don't do any backoff and reset the backoff timer
            retry_iter = retry_policy.clone().into_iter();
            continue;
        }

        tokio::select! {
            _ = token.cancelled() => {
                break
            }
            _ = tokio::time::sleep(retry_iter.next().unwrap()) => {}
        }
    }
}

fn round_robin_client(
    options: &Options,
    builder: &hyper_util::client::legacy::Builder,
    https_connector: &HttpsConnector<HttpConnector>,
) -> RoundRobinClient {
    // in order to avoid all traffic going to a single downstream destination:
    // - each tunnel server should have separate conn pool (this is similar to how different restate nodes would have different pools)
    // - in addition, we will give each server *multiple* http2 conns per pool (this is similar to separate partitions in restate having a conn each)
    let mut clients = Vec::with_capacity(options.pools_per_tunnel.get());

    for _ in 0..options.pools_per_tunnel.get() {
        clients.push(builder.build(https_connector.clone()));
    }

    RoundRobinClient::new(clients)
}

struct RoundRobinClient {
    clients: Vec<hyper_util::client::legacy::Client<HttpsConnector<HttpConnector>, Incoming>>,
    index: AtomicUsize,
}

impl RoundRobinClient {
    fn new(
        clients: Vec<hyper_util::client::legacy::Client<HttpsConnector<HttpConnector>, Incoming>>,
    ) -> Self {
        Self {
            clients,
            index: AtomicUsize::new(0),
        }
    }

    fn get(&self) -> &hyper_util::client::legacy::Client<HttpsConnector<HttpConnector>, Incoming> {
        let i = self.index.fetch_add(1, Ordering::Relaxed);
        &self.clients[i % self.clients.len()]
    }
}

const TUNNEL_TO_HEADER: http::HeaderName = http::HeaderName::from_static("x-restate-tunnel-to");

async fn do_proxy(
    client: hyper_util::client::legacy::Client<HttpsConnector<HttpConnector>, Incoming>,
    req: http::Request<Incoming>,
) -> Result<
    http::Response<
        impl hyper::body::Body<Data = Bytes, Error = Box<dyn std::error::Error + Send + Sync>>
        + Send
        + Sync
        + 'static,
    >,
    hyper_util::client::legacy::Error,
> {
    let tunnel_to = match req
        .headers()
        .get(TUNNEL_TO_HEADER)
        .and_then(|tunnel_to| tunnel_to.to_str().ok())
        .and_then(|tunnel_to| Uri::from_str(tunnel_to).ok())
    {
        Some(tunnel_to) => tunnel_to,
        None => {
            warn!("Tunnel request was missing a 'x-restate-tunnel-to' header");
            return Ok(http::Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(http_body_util::Either::Left(http_body_util::Empty::new()))
                .unwrap());
        }
    };

    let tunnel_to_parts = tunnel_to.into_parts();

    let (mut req_parts, req_body) = req.into_parts();
    let mut uri_parts = req_parts.uri.into_parts();

    uri_parts.scheme = tunnel_to_parts.scheme;
    uri_parts.authority = tunnel_to_parts.authority;

    req_parts.uri = Uri::from_parts(uri_parts).expect("passing through uri parts must not fail");

    let span = info_span!("client_request", destination = %req_parts.uri);
    let req = http::Request::from_parts(req_parts, req_body);

    async move {
        debug!("Proxying request");
        let response = match client.request(req).await {
            Ok(response) => {
                debug!("Proxied request with status {}", response.status());
                response
            }
            Err(err) => {
                error!("Failed to proxy request: {err}");
                return Err(err);
            }
        };

        Ok(response.map(http_body_util::Either::Right))
    }
    .instrument(span)
    .await
}
