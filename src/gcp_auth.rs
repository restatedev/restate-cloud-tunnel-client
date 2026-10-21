//! Google ID tokens for requests proxied from Restate Cloud to local services.
//!
//! Restate Cloud has no identity in the network the tunnel client runs in, but the client
//! does. With `gcp_auth` set, the client fetches an ID token for each https destination and
//! sets it as the `Authorization` header, so services behind the tunnel can require Cloud Run
//! invoker IAM in addition to the request signature.

use std::{
    collections::HashMap,
    sync::Mutex,
    time::{Duration, Instant},
};

use anyhow::{Context, bail};
use bytes::Bytes;
use http::{HeaderValue, Uri};
use http_body_util::{BodyExt, Empty};
use hyper_util::client::legacy::connect::HttpConnector;
use tracing::debug;

/// Google ID tokens are valid for one hour; refresh a little before that.
const GCP_ID_TOKEN_TTL: Duration = Duration::from_secs(50 * 60);
const GCP_METADATA_TIMEOUT: Duration = Duration::from_secs(5);
const GCP_METADATA_HOST: &str = "metadata.google.internal";
/// Override honoured by Google's client libraries; useful for tests.
const GCP_METADATA_HOST_ENV: &str = "GCE_METADATA_HOST";
const GCP_METADATA_IDENTITY_PATH: &str =
    "/computeMetadata/v1/instance/service-accounts/default/identity";

/// Mints Google ID tokens via the metadata server for the service account the client runs
/// as, cached per audience.
pub struct GcpIdTokenSource {
    client: hyper_util::client::legacy::Client<HttpConnector, Empty<Bytes>>,
    metadata_host: String,
    cache: Mutex<HashMap<String, CachedToken>>,
}

struct CachedToken {
    authorization: HeaderValue,
    fetched_at: Instant,
}

impl GcpIdTokenSource {
    pub fn new(connector: HttpConnector) -> Self {
        let metadata_host = std::env::var(GCP_METADATA_HOST_ENV)
            .ok()
            .filter(|host| !host.is_empty())
            .unwrap_or_else(|| GCP_METADATA_HOST.to_owned());
        Self::with_metadata_host(connector, metadata_host)
    }

    fn with_metadata_host(connector: HttpConnector, metadata_host: String) -> Self {
        let client =
            hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::default())
                .build(connector);
        Self {
            client,
            metadata_host,
            cache: Mutex::new(HashMap::new()),
        }
    }

    /// The token audience for `destination`, or `None` if it should be proxied without a
    /// credential. Only https destinations get one; Cloud Run expects the service url without
    /// port or path.
    pub fn audience(destination: &Uri) -> Option<String> {
        match (destination.scheme_str(), destination.host()) {
            (Some("https"), Some(host)) => Some(format!("https://{host}")),
            _ => None,
        }
    }

    /// An `Authorization` header value with an ID token for `audience`, fetched from the
    /// metadata server unless a fresh one is cached.
    pub async fn authorization(&self, audience: &str) -> anyhow::Result<HeaderValue> {
        if let Some(authorization) = self.cached(audience) {
            return Ok(authorization);
        }

        let token = self.fetch(audience).await?;
        let mut authorization = HeaderValue::from_str(&format!("Bearer {token}"))
            .context("metadata server returned a token that is not a valid header value")?;
        authorization.set_sensitive(true);

        self.cache.lock().unwrap().insert(
            audience.to_owned(),
            CachedToken {
                authorization: authorization.clone(),
                fetched_at: Instant::now(),
            },
        );
        debug!(audience, "Fetched GCP ID token");

        Ok(authorization)
    }

    fn cached(&self, audience: &str) -> Option<HeaderValue> {
        let cache = self.cache.lock().unwrap();
        let cached = cache.get(audience)?;
        (cached.fetched_at.elapsed() < GCP_ID_TOKEN_TTL).then(|| cached.authorization.clone())
    }

    async fn fetch(&self, audience: &str) -> anyhow::Result<String> {
        // ':' and '/' are allowed in a query; the builder rejects anything invalid
        let uri = Uri::builder()
            .scheme("http")
            .authority(self.metadata_host.as_str())
            .path_and_query(format!("{GCP_METADATA_IDENTITY_PATH}?audience={audience}"))
            .build()
            .context("failed to build metadata server uri")?;

        let request = http::Request::get(uri)
            .header("Metadata-Flavor", "Google")
            .body(Empty::new())
            .expect("metadata request to build");

        let response = tokio::time::timeout(GCP_METADATA_TIMEOUT, self.client.request(request))
            .await
            .context("timed out reaching the GCP metadata server")?
            .context("failed to reach the GCP metadata server")?;
        let status = response.status();
        let body = response
            .into_body()
            .collect()
            .await
            .context("failed to read the GCP metadata server response")?
            .to_bytes();

        if !status.is_success() {
            bail!(
                "GCP metadata server returned {status}: {}",
                String::from_utf8_lossy(&body).trim()
            );
        }

        let token = String::from_utf8(body.into())
            .context("GCP metadata server returned a non-utf8 token")?;
        let token = token.trim();
        if token.is_empty() {
            bail!("GCP metadata server returned an empty token");
        }

        Ok(token.to_owned())
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::HashMap,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
    };

    use axum::{
        Router,
        extract::{Query, State},
        http::{HeaderMap, StatusCode},
        routing::get,
    };
    use hyper_util::client::legacy::connect::HttpConnector;

    use super::*;

    #[derive(Clone)]
    struct FakeMetadata {
        calls: Arc<AtomicUsize>,
        fail: bool,
    }

    async fn identity(
        State(fake): State<FakeMetadata>,
        headers: HeaderMap,
        Query(query): Query<HashMap<String, String>>,
    ) -> (StatusCode, String) {
        fake.calls.fetch_add(1, Ordering::SeqCst);

        if headers.get("metadata-flavor").map(HeaderValue::as_bytes) != Some(b"Google".as_slice()) {
            return (StatusCode::FORBIDDEN, "missing Metadata-Flavor".to_owned());
        }
        if fake.fail {
            return (StatusCode::INTERNAL_SERVER_ERROR, "boom".to_owned());
        }
        match query.get("audience") {
            Some(audience) => (StatusCode::OK, format!("token-for-{audience}\n")),
            None => (StatusCode::BAD_REQUEST, "missing audience".to_owned()),
        }
    }

    async fn start(fail: bool) -> (GcpIdTokenSource, Arc<AtomicUsize>) {
        let fake = FakeMetadata {
            calls: Arc::default(),
            fail,
        };
        let calls = fake.calls.clone();

        let router = Router::new()
            .route(GCP_METADATA_IDENTITY_PATH, get(identity))
            .with_state(fake);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(axum::serve(listener, router).into_future());

        let source =
            GcpIdTokenSource::with_metadata_host(HttpConnector::new(), address.to_string());
        (source, calls)
    }

    #[test]
    fn audience_is_https_host_without_port() {
        let uri = Uri::from_static("https://svc-abc.a.run.app:443/invoke?x=1");
        assert_eq!(
            GcpIdTokenSource::audience(&uri),
            Some("https://svc-abc.a.run.app".to_owned())
        );
    }

    #[test]
    fn audience_is_none_for_cleartext() {
        let uri = Uri::from_static("http://my-service.default.svc.cluster.local:9080/invoke");
        assert_eq!(GcpIdTokenSource::audience(&uri), None);
    }

    #[tokio::test]
    async fn fetches_bearer_token_and_caches_per_audience() {
        let (source, calls) = start(false).await;

        let first = source
            .authorization("https://svc-abc.a.run.app")
            .await
            .unwrap();
        assert_eq!(first, "Bearer token-for-https://svc-abc.a.run.app");
        assert!(first.is_sensitive());

        let second = source
            .authorization("https://svc-abc.a.run.app")
            .await
            .unwrap();
        assert_eq!(second, first);
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "second call should hit the cache"
        );

        let other = source
            .authorization("https://other.a.run.app")
            .await
            .unwrap();
        assert_eq!(other, "Bearer token-for-https://other.a.run.app");
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn expired_cache_entry_is_refreshed() {
        let (source, calls) = start(false).await;
        let audience = "https://svc-abc.a.run.app";

        source.authorization(audience).await.unwrap();
        source
            .cache
            .lock()
            .unwrap()
            .get_mut(audience)
            .unwrap()
            .fetched_at = Instant::now() - GCP_ID_TOKEN_TTL;

        source.authorization(audience).await.unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn metadata_server_error_is_reported_and_not_cached() {
        let (source, calls) = start(true).await;

        let err = source
            .authorization("https://svc-abc.a.run.app")
            .await
            .unwrap_err();
        assert!(err.to_string().contains("500"), "{err}");

        let _ = source.authorization("https://svc-abc.a.run.app").await;
        assert_eq!(
            calls.load(Ordering::SeqCst),
            2,
            "failures must not be cached"
        );
    }

    #[tokio::test]
    async fn unreachable_metadata_server_is_reported() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        drop(listener);

        let source =
            GcpIdTokenSource::with_metadata_host(HttpConnector::new(), address.to_string());
        let err = source
            .authorization("https://svc-abc.a.run.app")
            .await
            .unwrap_err();
        assert!(err.to_string().contains("metadata server"), "{err}");
    }
}
