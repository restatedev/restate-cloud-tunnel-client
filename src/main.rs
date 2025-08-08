use std::{
    collections::HashMap,
    fmt::Display,
    num::NonZeroUsize,
    path::PathBuf,
    str::FromStr,
    sync::{
        Arc, RwLock,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use axum::response::IntoResponse;
use bytes::{BufMut, Bytes, BytesMut};
use clap::Parser;
use futures::{FutureExt, StreamExt};
use http::{Request, Response, StatusCode, Uri};
use hyper::body::Incoming;
use hyper_rustls::HttpsConnector;
use hyper_util::client::legacy::connect::HttpConnector;
use restate_cloud_tunnel_client::client::{
    Handler, HandlerNotification, ServeError, TLS_CLIENT_CONFIG,
};
use restate_types::retries::RetryPolicy;
use serde::Serialize;
use tokio::sync::watch;
use tokio_util::{sync::CancellationToken, task::TaskTracker};
use tracing::{Instrument, debug, debug_span, error, info, info_span, warn};
use tracing_subscriber::filter::LevelFilter;

use crate::{options::Options, signal::shutdown};

mod options;
mod signal;
mod srv;

const HTTP_VERSION: http::HeaderName =
    http::HeaderName::from_static("x-restate-tunnel-http-version");

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
        .http2_initial_max_send_streams(options.initial_max_send_streams)
        .http2_adaptive_window(true)
        .http2_keep_alive_timeout(options.http_keep_alive_options.timeout.into())
        .http2_keep_alive_interval(Some(options.http_keep_alive_options.interval.into()));

    let mut http_connector = HttpConnector::new();
    http_connector.enforce_http(false);
    http_connector.set_nodelay(true);
    http_connector.set_connect_timeout(Some(options.connect_timeout));

    let https_alpn_connector = hyper_rustls::HttpsConnectorBuilder::new()
        .with_tls_config(TLS_CLIENT_CONFIG.clone())
        .https_or_http()
        .enable_http1()
        .enable_http2()
        .wrap_connector(http_connector.clone());

    let https_h1_connector = hyper_rustls::HttpsConnectorBuilder::new()
        .with_tls_config(TLS_CLIENT_CONFIG.clone())
        .https_or_http()
        .enable_http1()
        .wrap_connector(http_connector.clone());

    let https_h2_connector = hyper_rustls::HttpsConnectorBuilder::new()
        .with_tls_config(TLS_CLIENT_CONFIG.clone())
        .https_or_http()
        .enable_http2()
        .wrap_connector(http_connector.clone());

    let uris = Arc::new(RwLock::new(HashMap::new()));
    let connections = TaskTracker::new();
    let token = CancellationToken::new();
    let mut shutdown_fut = std::pin::pin!(shutdown());

    let http1_or_http2_builder = builder.clone();
    // we can use a single http1.1 client as the connection reuse behaviour handles multiple ips well
    let http1_client = http1_or_http2_builder.build(https_h1_connector);
    let http2_builder = builder.http2_only(true);

    {
        let router = axum::Router::new()
            .route("/health", axum::routing::get(health))
            .with_state(HealthState { uris: uris.clone() });

        let server = axum::serve(
            tokio::net::TcpListener::bind(options.health_serve_address).await?,
            router.into_make_service(),
        )
        .with_graceful_shutdown(token.clone().cancelled_owned());

        info!(
            address = %options.health_serve_address,
            "Serving health endpoint"
        );

        tokio::spawn(connections.track_future(server.into_future()));
    };

    let authorization = {
        let authorization: &'static str =
            Box::leak(Box::<str>::from(format!("Bearer {}", options.bearer_token)));
        let mut authorization = http::HeaderValue::from_static(authorization);
        authorization.set_sensitive(true);
        authorization
    };

    if options.remote_proxy {
        {
            let router = axum::Router::new()
                .fallback(remote_proxy)
                .with_state(Arc::new(ProxyState {
                    base_uri: options.ingress_uri.clone(),
                    // for calls to restate cloud, we use 6 conns so we have a fair spread over the 3 nlb ips
                    client: round_robin_client(
                        NonZeroUsize::new(6).unwrap(),
                        http2_builder,
                        &https_alpn_connector,
                    ),
                    authorization: authorization.clone(),
                }));

            let server = axum::serve(
                tokio::net::TcpListener::bind(options.ingress_serve_address).await?,
                router.into_make_service(),
            )
            .with_graceful_shutdown(token.clone().cancelled_owned());

            info!(
                address = %options.ingress_serve_address,
                destination = %options.ingress_uri,
                "Serving ingress proxy endpoint"
            );

            tokio::spawn(connections.track_future(server.into_future()));
        };

        {
            let router = axum::Router::new()
                .fallback(remote_proxy)
                .with_state(Arc::new(ProxyState {
                    base_uri: options.admin_uri.clone(),
                    // for calls to restate cloud, we use 6 conns so we have a fair spread over the 3 nlb ips
                    client: round_robin_client(
                        NonZeroUsize::new(6).unwrap(),
                        http2_builder,
                        &https_alpn_connector,
                    ),
                    authorization,
                }));

            let server = axum::serve(
                tokio::net::TcpListener::bind(options.admin_serve_address).await?,
                router.into_make_service(),
            )
            .with_graceful_shutdown(token.clone().cancelled_owned());

            info!(
                address = %options.admin_serve_address,
                destination = %options.admin_uri,
                "Serving admin proxy endpoint"
            );

            tokio::spawn(connections.track_future(server.into_future()));
        };
    } else {
        info!("Not proxying local ports to Restate Cloud as RESTATE_REMOTE_PROXY is false");
    }

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

        {
            let uris_read = uris.read().unwrap();
            if tunnel_servers
                .iter()
                .all(|server| uris_read.contains_key(server))
                && tunnel_servers.len() == uris_read.len()
            {
                // don't bother taking a write lock if there is no change in the tunnels
                continue;
            }
        }

        let mut uris = uris.write().unwrap();

        for server in &tunnel_servers {
            if uris.contains_key(server) {
                continue;
            }

            info!(%server, "Starting new tunnel");

            let (status_send, status_recv) = watch::channel(TunnelStatus::Opening);
            let token = token.child_token();

            let alpn_client = round_robin_client(
                options.pools_per_tunnel,
                &http1_or_http2_builder,
                &https_alpn_connector,
            );
            let http1_client = http1_client.clone();
            let http2_client = round_robin_client(
                options.pools_per_tunnel,
                http2_builder,
                &https_h2_connector,
            );

            let handler = Handler::<(), ()>::new(
                hyper::service::service_fn(move |req| {
                    local_proxy(&alpn_client, &http1_client, &http2_client, req)
                }),
                options.connect_timeout,
                &options.environment_id,
                &options.signing_public_key,
                &options.bearer_token,
                Some(options.tunnel_name.clone()),
                Option::<fn(_)>::None,
            )
            .expect("failed to create tunnel handler");

            let fut = handle_tunnel_uri(handler, token.clone(), status_send, server.clone())
                .instrument(info_span!("tunnel", server = %server).or_current());

            tokio::spawn(connections.track_future(fut));
            uris.insert(server.clone(), (token, status_recv));
        }

        uris.retain(|existing_uri, (token, _)| {
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

#[derive(Clone)]
struct HealthState {
    #[allow(clippy::type_complexity)]
    uris: Arc<RwLock<HashMap<Uri, (CancellationToken, watch::Receiver<TunnelStatus>)>>>,
}

#[serde_with::serde_as]
#[derive(Serialize)]
struct HealthOutput(
    #[serde_as(as = "HashMap<serde_with::DisplayFromStr, _>")] HashMap<Uri, TunnelStatus>,
);

async fn health(
    axum::extract::State(state): axum::extract::State<HealthState>,
) -> axum::response::Response {
    match state.uris.read() {
        Ok(uris) => {
            let mut statuses = HashMap::new();
            let mut all_open = true;
            for (uri, (_, receiver)) in uris.iter() {
                let status = *receiver.borrow();
                statuses.insert(uri.clone(), status);
                if !matches!(status, TunnelStatus::Open) {
                    all_open = false
                }
            }
            if all_open && !statuses.is_empty() {
                axum::Json(HealthOutput(statuses)).into_response()
            } else {
                let mut resp = axum::Json(HealthOutput(statuses)).into_response();
                *resp.status_mut() = http::StatusCode::INTERNAL_SERVER_ERROR;
                resp
            }
        }
        Err(_) => {
            let mut resp = "poisoned".into_response();
            *resp.status_mut() = http::StatusCode::INTERNAL_SERVER_ERROR;
            resp
        }
    }
}

struct ProxyState {
    base_uri: Uri,
    client: RoundRobinClient<axum::body::Body>,
    authorization: http::HeaderValue,
}

async fn remote_proxy(
    axum::extract::State(state): axum::extract::State<Arc<ProxyState>>,
    req: http::Request<axum::body::Body>,
) -> http::Response<
    impl hyper::body::Body<Data = Bytes, Error = Box<dyn std::error::Error + Send + Sync>>
    + Send
    + Sync
    + 'static,
> {
    let (mut head, body) = req.into_parts();
    remote_proxy_headers(&mut head.headers, state.authorization.clone());
    head.version = http::Version::HTTP_2;

    let mut uri_parts = head.uri.into_parts();
    uri_parts.scheme = state.base_uri.scheme().cloned();
    uri_parts.authority = state.base_uri.authority().cloned();
    let Ok(uri) = Uri::from_parts(uri_parts) else {
        return http::Response::builder()
            .status(http::StatusCode::BAD_REQUEST)
            .body(http_body_util::Either::Left(http_body_util::Empty::new()))
            .expect("http response to build");
    };
    head.uri = uri;

    let req = http::Request::from_parts(head, body);

    let span = debug_span!("remote_request", destination = %req.uri());

    async {
        let result = match state.client.get().request(req).await {
            Ok(result) => result,
            Err(err) => {
                debug!(%err, "Failed to proxy request to Restate Cloud");

                return http::Response::builder()
                    .status(http::StatusCode::BAD_GATEWAY)
                    .body(http_body_util::Either::Left(http_body_util::Empty::new()))
                    .expect("http response to build");
            }
        };

        debug!(
            status = result.status().as_u16(),
            "Proxied request to Restate Cloud",
        );
        result.map(http_body_util::Either::Right)
    }
    .instrument(span)
    .await
}

// https://httptoolkit.com/blog/translating-http-2-into-http-1/
static BLOCK_HEADERS: [http::HeaderName; 6] = [
    http::header::CONNECTION,
    http::header::TRANSFER_ENCODING,
    http::header::UPGRADE,
    http::HeaderName::from_static("keep-alive"),
    http::HeaderName::from_static("proxy-connection"),
    http::HeaderName::from_static("http2-settings"),
];

fn remote_proxy_headers(headers: &mut http::HeaderMap, authorization: http::HeaderValue) {
    let old_host = headers.remove(http::header::HOST);

    for header in &BLOCK_HEADERS {
        headers.remove(header);
    }

    // https://httptoolkit.com/blog/translating-http-2-into-http-1/
    match headers.get(http::header::TE) {
        Some(t) if t == "trailers" => {}
        None => {}
        _ => {
            headers.remove(http::header::TE);
        }
    }

    if let Some(old_host) = old_host {
        headers.insert(http::HeaderName::from_static("x-forwarded-host"), old_host);
    }

    headers.insert(http::header::AUTHORIZATION, authorization);
}

#[derive(Clone, Copy, Serialize)]
enum TunnelStatus {
    Opening,
    Open,
    BackingOff,
    Cancelled,
}

async fn handle_tunnel_uri<Notify, Client, ClientError, ClientFuture, ResponseBody>(
    handler: Handler<Notify, Client>,
    token: CancellationToken,
    status: watch::Sender<TunnelStatus>,
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
        // default connect timeout 5s, tunnel handshake timeout 5s
        let mut opened_after = std::pin::pin!(tokio::time::sleep(Duration::from_secs(15)));
        let mut opened = false;

        loop {
            tokio::select! {
                _ = &mut opened_after, if !opened => {
                    let _ = status.send(TunnelStatus::Open);
                    opened = true;
                }
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
                    break
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
                    info!("Server requested drain; starting new tunnel connection");
                    break
                }
            }
        }

        if opened {
            // if the tunnel ran for a reasonable amount of time, reset the backoff timer
            retry_iter = retry_policy.clone().into_iter();
        }

        let _ = status.send(TunnelStatus::BackingOff);

        tokio::select! {
            _ = token.cancelled() => {
                let _ = status.send(TunnelStatus::Cancelled);
                break
            }
            _ = tokio::time::sleep(retry_iter.next().unwrap()) => {
                let _ = status.send(TunnelStatus::Opening);
            }
        }
    }
}

fn round_robin_client<B: hyper::body::Body + Send>(
    count: NonZeroUsize,
    builder: &hyper_util::client::legacy::Builder,
    https_connector: &HttpsConnector<HttpConnector>,
) -> RoundRobinClient<B>
where
    B::Data: Send,
{
    let count = count.get();
    // in order to avoid all traffic going to a single downstream destination:
    // - each tunnel server should have separate conn pool (this is similar to how different restate nodes would have different pools)
    // - in addition, we will give each server *multiple* http2 conns per pool (this is similar to separate partitions in restate having a conn each)
    let mut clients = Vec::with_capacity(count);

    for _ in 0..count {
        clients.push(builder.build(https_connector.clone()));
    }

    RoundRobinClient::new(clients)
}

struct RoundRobinClient<B> {
    clients: Vec<hyper_util::client::legacy::Client<HttpsConnector<HttpConnector>, B>>,
    index: AtomicUsize,
}

impl<B> RoundRobinClient<B> {
    fn new(
        clients: Vec<hyper_util::client::legacy::Client<HttpsConnector<HttpConnector>, B>>,
    ) -> Self {
        Self {
            clients,
            index: AtomicUsize::new(0),
        }
    }

    fn get(&self) -> &hyper_util::client::legacy::Client<HttpsConnector<HttpConnector>, B> {
        let i = self.index.fetch_add(1, Ordering::Relaxed);
        &self.clients[i % self.clients.len()]
    }
}

fn local_proxy(
    alpn_client: &RoundRobinClient<Incoming>,
    http1_client: &hyper_util::client::legacy::Client<HttpsConnector<HttpConnector>, Incoming>,
    http2_client: &RoundRobinClient<Incoming>,
    req: http::Request<Incoming>,
) -> impl Future<
    Output = Result<
        http::Response<
            impl hyper::body::Body<Data = Bytes, Error = Box<dyn std::error::Error + Send + Sync>>
            + Send
            + Sync
            + 'static
            + use<>,
        >,
        hyper_util::client::legacy::Error,
    >,
>
+ 'static
+ use<> {
    let (mut head, body) = req.into_parts();

    let Some(path_and_query) = head.uri.path_and_query() else {
        warn!(uri = %head.uri, "Tunnel request was missing path");
        return std::future::ready(Ok(http::Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(http_body_util::Either::Left(http_body_util::Empty::new()))
            .unwrap()))
        .left_future();
    };

    let destination = match parse_tunnel_destination(path_and_query) {
        Ok(destination) => destination,
        Err(message) => {
            warn!(uri = %head.uri, "Tunnel request had an invalid path ({})", message);
            return std::future::ready(Ok(http::Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(http_body_util::Either::Left(http_body_util::Empty::new()))
                .unwrap()))
            .left_future();
        }
    };

    head.uri = destination;

    let client = match (
        head.uri.scheme_str(),
        head.headers
            .get(HTTP_VERSION)
            .map(http::HeaderValue::as_bytes),
    ) {
        // https urls will use an alpn client which supports http2 via alpn and http1.1, unless the user requested a particular version
        (Some("https"), None) => {
            // we don't want to force HTTP2 as we don't know if the destination accepts it
            // a request with HTTP_11 can still end up using h2 if the alpn agrees
            head.version = http::Version::HTTP_11;
            alpn_client.get()
        }
        // cleartext requests where the user didn't request a specific version; use http2 prior-knowledge
        (_, None) => {
            head.version = http::Version::HTTP_2;
            http2_client.get()
        }
        // https or cleartext requests where the user requested http2; use http2
        // prior-knowledge for cleartext, h2 in alpn otherwise
        (_, Some(b"HTTP/2.0")) => {
            head.version = http::Version::HTTP_2;
            http2_client.get()
        }
        // https or cleartext requests where the user requested http1.1; use http1.1
        // will not use h2 even if the alpn supports it
        (_, Some(b"HTTP/1.1")) => {
            head.version = http::Version::HTTP_11;
            http1_client
        }
        (_, Some(other)) => {
            warn!(uri = %head.uri, "Tunnel request had an invalid x-restate-tunnel-http-version ({})", String::from_utf8_lossy(other));
            return std::future::ready(Ok(http::Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(http_body_util::Either::Left(http_body_util::Empty::new()))
                .unwrap()))
            .left_future();
        }
    };

    let req = http::Request::from_parts(head, body);

    let span = debug_span!("local_request", destination = %req.uri());

    let fut = client.request(req);

    async move {
        match fut.await {
            Ok(response) => {
                debug!(
                    status = response.status().as_u16(),
                    "Proxied request from Restate Cloud"
                );
                Ok(response.map(http_body_util::Either::Right))
            }
            Err(err) => {
                error!(%err, "Failed to proxy request from Restate Cloud");

                Ok(http::Response::builder()
                    .status(StatusCode::BAD_GATEWAY)
                    .body(http_body_util::Either::Left(http_body_util::Empty::new()))
                    .unwrap())
            }
        }
    }
    .instrument(span)
    .right_future()
}

fn parse_tunnel_destination(path_and_query: &http::uri::PathAndQuery) -> Result<Uri, &'static str> {
    let path = path_and_query
        .path()
        .strip_prefix('/')
        .ok_or("no leading /")?;
    let (scheme, path) = path.split_once("/").ok_or("no host")?;
    let scheme = http::uri::Scheme::from_str(scheme)
        .ok()
        .ok_or("invalid scheme")?;
    let (host, path) = path.split_once("/").ok_or("no port")?;

    let (port, path) = match path.split_once("/") {
        Some((port, path)) => (port, path),
        None => (path, ""),
    };

    let mut authority = BytesMut::with_capacity(host.len() + 1 + port.len());
    authority.put(host.as_bytes());
    authority.put(&b":"[..]);
    authority.put(port.as_bytes());

    let authority = http::uri::Authority::from_maybe_shared(authority.freeze())
        .ok()
        .ok_or("invalid authority")?;

    let path_and_query = if let Some(query) = path_and_query.query() {
        let mut path_and_query = BytesMut::with_capacity(1 + path.len() + 1 + query.len());
        path_and_query.put(&b"/"[..]);
        path_and_query.put(path.as_bytes());
        path_and_query.put(&b"?"[..]);
        path_and_query.put(query.as_bytes());

        http::uri::PathAndQuery::from_maybe_shared(path_and_query.freeze())
    } else {
        let mut path_and_query = BytesMut::with_capacity(1 + path.len());
        path_and_query.put(&b"/"[..]);
        path_and_query.put(path.as_bytes());

        http::uri::PathAndQuery::from_maybe_shared(path_and_query.freeze())
    };
    let path_and_query = path_and_query.ok().ok_or("invalid path")?;

    Uri::builder()
        .scheme(scheme)
        .authority(authority)
        .path_and_query(path_and_query)
        .build()
        .ok()
        .ok_or("invalid uri")
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::uri::PathAndQuery;

    #[test]
    fn test_parse_tunnel_destination_valid_http() {
        let path_and_query =
            PathAndQuery::from_static("/http/example.com/8080/api/v1/users?id=123");
        let result = parse_tunnel_destination(&path_and_query).unwrap();

        assert_eq!(result.scheme_str(), Some("http"));
        assert_eq!(result.authority().unwrap().as_str(), "example.com:8080");
        assert_eq!(
            result.path_and_query().unwrap().as_str(),
            "/api/v1/users?id=123"
        );
    }

    #[test]
    fn test_parse_tunnel_destination_valid_https() {
        let path_and_query = PathAndQuery::from_static("/https/api.example.com/443/v2/data");
        let result = parse_tunnel_destination(&path_and_query).unwrap();

        assert_eq!(result.scheme_str(), Some("https"));
        assert_eq!(result.authority().unwrap().as_str(), "api.example.com:443");
        assert_eq!(result.path_and_query().unwrap().as_str(), "/v2/data");
    }

    #[test]
    fn test_parse_tunnel_destination_root_path() {
        let path_and_query = PathAndQuery::from_static("/http/localhost/3000");
        let result = parse_tunnel_destination(&path_and_query).unwrap();

        assert_eq!(result.scheme_str(), Some("http"));
        assert_eq!(result.authority().unwrap().as_str(), "localhost:3000");
        assert_eq!(result.path_and_query().unwrap().as_str(), "/");
    }

    #[test]
    fn test_parse_tunnel_destination_with_query_no_path() {
        let path_and_query = PathAndQuery::from_static("/https/example.com/443?query=value");
        let result = parse_tunnel_destination(&path_and_query).unwrap();

        assert_eq!(result.scheme_str(), Some("https"));
        assert_eq!(result.authority().unwrap().as_str(), "example.com:443");
        assert_eq!(result.path_and_query().unwrap().as_str(), "/?query=value");
    }

    #[test]
    fn test_parse_tunnel_destination_missing_leading_slash() {
        let path_and_query = PathAndQuery::from_static("http/example.com/8080/api");
        let result = parse_tunnel_destination(&path_and_query);

        assert_eq!(result, Err("no leading /"));
    }

    #[test]
    fn test_parse_tunnel_destination_no_host() {
        let path_and_query = PathAndQuery::from_static("/http");
        let result = parse_tunnel_destination(&path_and_query);

        assert_eq!(result, Err("no host"));
    }

    #[test]
    fn test_parse_tunnel_destination_invalid_scheme() {
        let path_and_query = PathAndQuery::from_static("/!/example.com/8080/api");
        let result = parse_tunnel_destination(&path_and_query);

        assert_eq!(result, Err("invalid scheme"));
    }

    #[test]
    fn test_parse_tunnel_destination_no_port() {
        let path_and_query = PathAndQuery::from_static("/http/example.com");
        let result = parse_tunnel_destination(&path_and_query);

        assert_eq!(result, Err("no port"));
    }

    #[test]
    fn test_parse_tunnel_destination_complex_path() {
        let path_and_query = PathAndQuery::from_static(
            "/https/api.service.com/443/v1/users/123/posts?limit=10&offset=20",
        );
        let result = parse_tunnel_destination(&path_and_query).unwrap();

        assert_eq!(result.scheme_str(), Some("https"));
        assert_eq!(result.authority().unwrap().as_str(), "api.service.com:443");
        assert_eq!(
            result.path_and_query().unwrap().as_str(),
            "/v1/users/123/posts?limit=10&offset=20"
        );
    }
}
