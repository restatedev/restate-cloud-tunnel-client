use std::{
    collections::{HashMap, HashSet},
    fmt::Display,
    str::FromStr,
    time::{Duration, Instant},
};

use futures::{Stream, StreamExt, TryStreamExt, stream::FuturesUnordered};
use hickory_resolver::{Name, lookup_ip::LookupIp};
use http::{
    Uri,
    uri::{PathAndQuery, Scheme},
};
use tracing::{debug, error};

#[derive(Clone)]
pub struct ServerName(rustls::pki_types::ServerName<'static>);

impl Display for ServerName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0.to_str())
    }
}

impl FromStr for ServerName {
    type Err = rustls::pki_types::InvalidDnsNameError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(rustls::pki_types::ServerName::try_from(s)?.to_owned()))
    }
}

impl From<ServerName> for rustls::pki_types::ServerName<'static> {
    fn from(value: ServerName) -> Self {
        value.0
    }
}

pub fn fixed_uri_stream(
    uris: HashMap<Uri, ServerName>,
) -> impl Stream<Item = HashMap<Uri, ServerName>> {
    futures::stream::once(futures::future::ready(uris)).chain(futures::stream::pending())
}

pub trait Resolver: Sized {
    async fn resolve_srv(&self, srv: Name) -> anyhow::Result<(HashSet<Uri>, Instant)>;

    fn into_stream(self, srv: Name) -> impl Stream<Item = HashMap<Uri, ServerName>> {
        futures::stream::unfold((self, srv, None), async |(resolver, srv, valid_until)| {
            if let Some(valid_until) = valid_until {
                tokio::time::sleep_until(tokio::time::Instant::from(valid_until)).await
            }

            loop {
                let (uris, valid_until) = match resolver.resolve_srv(srv.clone()).await {
                    Ok(lookup) => lookup,
                    Err(err) => {
                        error!("Failed to resolve SRV record {srv}: {err}");
                        tokio::time::sleep(Duration::from_secs(5)).await;
                        continue;
                    }
                };

                debug!(
                    "Resolved SRV record {srv} into {} uris with validity for {:?}",
                    uris.len(),
                    valid_until
                        .checked_duration_since(std::time::Instant::now())
                        .unwrap_or(std::time::Duration::ZERO)
                );

                let server_name = ServerName(rustls::pki_types::ServerName::DnsName(
                    srv.to_utf8()
                        .try_into()
                        .expect("hickory dns name must be a valid rustls dns name"),
                ));

                let uris_with_name = uris
                    .into_iter()
                    .map(|uri| (uri, server_name.clone()))
                    .collect();

                break Some((uris_with_name, (resolver, srv, Some(valid_until))));
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

enum LookupOrNegativeTTL {
    LookupIP(LookupIp),
    NegativeTTL(Instant),
}

impl LookupOrNegativeTTL {
    fn valid_until(&self) -> Instant {
        match self {
            LookupOrNegativeTTL::LookupIP(lookup_ip) => lookup_ip.valid_until(),
            LookupOrNegativeTTL::NegativeTTL(instant) => *instant,
        }
    }
}

impl Resolver for HickoryResolver {
    async fn resolve_srv(&self, srv: Name) -> anyhow::Result<(HashSet<Uri>, Instant)> {
        let lookup = self.0.srv_lookup(srv.clone()).await?;

        let targets: HashSet<_> = lookup
            .iter()
            .map(|record| record.target().clone())
            .collect();

        let a_records: HashMap<_, _> = targets
            .into_iter()
            .map(|target| async {
                let records = match self.0.lookup_ip(target.clone()).await {
                    Ok(records) => LookupOrNegativeTTL::LookupIP(records),
                    Err(err) if err.is_no_records_found() || err.is_nx_domain() => {
                        let negative_ttl =
                            if let hickory_resolver::proto::ProtoErrorKind::NoRecordsFound {
                                negative_ttl: Some(negative_ttl),
                                ..
                            } = err.proto().unwrap().kind()
                            {
                                Duration::from_secs(*negative_ttl as u64)
                            } else {
                                // we default to waiting 60s to query again after a nxdomain
                                Duration::from_secs(60)
                            };

                        LookupOrNegativeTTL::NegativeTTL(
                            Instant::now()
                                .checked_add(negative_ttl)
                                .expect("time to not overflow"),
                        )
                    }
                    Err(err) => return Err(err.into()),
                };

                Result::<_, anyhow::Error>::Ok((target, records))
            })
            .collect::<FuturesUnordered<_>>()
            .try_collect()
            .await?;

        let uris = lookup
            .iter()
            .filter_map(
                |srv_record| match a_records.get(srv_record.target()).unwrap() {
                    LookupOrNegativeTTL::LookupIP(lookup_ip) => Some((srv_record, lookup_ip)),
                    LookupOrNegativeTTL::NegativeTTL(_) => None,
                },
            )
            .flat_map(|(srv_record, a_records)| {
                a_records.iter().map(|a_record| {
                    let uri = Uri::builder()
                        .scheme(Scheme::HTTPS)
                        .path_and_query(PathAndQuery::from_static("/"))
                        .authority(format!("{}:{}", a_record, srv_record.port()).as_str())
                        .build()
                        .map_err(anyhow::Error::from)?;

                    Result::<_, anyhow::Error>::Ok(uri)
                })
            })
            .collect::<Result<_, _>>()?;

        let valid_until = if let Some(valid_until) =
            a_records.values().map(|lookup| lookup.valid_until()).min()
        {
            valid_until.min(lookup.as_lookup().valid_until())
        } else {
            lookup.as_lookup().valid_until()
        };

        Ok((uris, valid_until))
    }
}
