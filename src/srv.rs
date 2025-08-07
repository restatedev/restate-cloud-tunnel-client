use std::{
    collections::HashSet,
    time::{Duration, Instant},
};

use futures::{Stream, StreamExt};
use hickory_resolver::Name;
use http::{
    Uri,
    uri::{PathAndQuery, Scheme},
};
use tracing::{debug, error};

pub fn fixed_uri_stream(uris: HashSet<Uri>) -> impl Stream<Item = HashSet<Uri>> {
    futures::stream::once(futures::future::ready(uris)).chain(futures::stream::pending())
}

pub trait Resolver: Sized {
    async fn resolve(&self, srv: Name) -> anyhow::Result<(HashSet<Uri>, Instant)>;

    fn into_stream(self, srv: Name) -> impl Stream<Item = HashSet<Uri>> {
        futures::stream::unfold((self, srv, None), async |(resolver, srv, valid_until)| {
            if let Some(valid_until) = valid_until {
                tokio::time::sleep_until(tokio::time::Instant::from(valid_until)).await
            }

            loop {
                let (uris, valid_until) = match resolver.resolve(srv.clone()).await {
                    Ok(lookup) => lookup,
                    Err(err) => {
                        error!("Failed to resolve SRV record {srv}: {err}");
                        tokio::time::sleep(Duration::from_secs(5)).await;
                        continue;
                    }
                };

                debug!("Resolved SRV record {srv} into {} uris", uris.len());

                break Some((uris, (resolver, srv, Some(valid_until))));
            }
        })
    }
}

pub struct HickoryResolver(
    hickory_resolver::Resolver<hickory_resolver::name_server::TokioConnectionProvider>,
);

impl HickoryResolver {
    pub fn new() -> Self {
        Self(hickory_resolver::Resolver::builder_tokio().unwrap().build())
    }
}

impl Resolver for HickoryResolver {
    async fn resolve(&self, srv: Name) -> anyhow::Result<(HashSet<Uri>, Instant)> {
        let lookup = self.0.srv_lookup(srv.clone()).await?;

        let uris = lookup
            .iter()
            .map(|record| {
                Uri::builder()
                    .scheme(Scheme::HTTPS)
                    .path_and_query(PathAndQuery::from_static("/"))
                    .authority(format!("{}:{}", record.target(), record.port()).as_str())
                    .build()
                    .map_err(anyhow::Error::from)
            })
            .collect::<Result<_, _>>()?;
        let valid_until = lookup.as_lookup().valid_until();

        Ok((uris, valid_until))
    }
}
