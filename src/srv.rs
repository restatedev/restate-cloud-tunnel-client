use std::{
    collections::{HashMap, HashSet},
    fmt::Display,
    net::IpAddr,
    str::FromStr,
    time::{Duration, Instant},
};

use futures::{Stream, StreamExt, TryStreamExt, stream::FuturesUnordered};
use hickory_resolver::{
    TokioResolver,
    config::LookupIpStrategy,
    lookup::Lookup,
    lookup_ip::LookupIp,
    net::{DnsError, NetError},
    proto::{
        op::ResponseCode,
        rr::{DNSClass, Name, RData, Record, RecordType},
    },
};
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

#[cfg(test)]
mod tests;

pub struct HickoryResolver(TokioResolver);

impl HickoryResolver {
    pub fn new() -> Self {
        // Both steps are fallible: reading the system configuration and validating the
        // resulting options. The resolver is a process-wide singleton, so fail loudly.
        let mut builder =
            TokioResolver::builder_tokio().expect("system resolver configuration must be readable");
        // Pin the old resolver defaults that changed in hickory-resolver 0.26:
        // keep the 32-entry cache and the effective 33 in-flight request guard, and
        // prefer IPv4 so an IPv6-only answer cannot replace a working IPv4 endpoint.
        builder.options_mut().ip_strategy = LookupIpStrategy::Ipv4thenIpv6;
        builder.options_mut().cache_size = 32;
        builder.options_mut().max_active_requests = 33;
        #[cfg(windows)]
        {
            // Windows has no resolver options file, so the parsed options retain the
            // 0.26 default of EDNS enabled; 0.25 defaulted to disabled there.
            builder.options_mut().edns0 = false;
        }
        Self(
            builder
                .build()
                .expect("system resolver configuration must be valid"),
        )
    }
}

/// The outcome of resolving one SRV target, with the expiry it contributes.
enum TargetResolution {
    /// Usable addresses for the target plus the deadline of the accepted records.
    Addresses {
        addresses: Vec<IpAddr>,
        valid_until: Instant,
    },
    /// The target is known not to exist; omit it and re-query after `valid_until`.
    Negative { valid_until: Instant },
}

impl TargetResolution {
    fn valid_until(&self) -> Instant {
        match self {
            TargetResolution::Addresses { valid_until, .. }
            | TargetResolution::Negative { valid_until } => *valid_until,
        }
    }
}

/// Server response codes that 0.25 reported as a negative answer without a negative TTL
/// (`ProtoErrorKind::NoRecordsFound { negative_ttl: None, .. }`). For those, and only
/// those, the old client omitted the target and retried it after 60 seconds instead of
/// failing the whole discovery. Everything else stays a hard error.
const SERVER_ERROR_RETRY_CODES: &[ResponseCode] = &[
    ResponseCode::ServFail,
    ResponseCode::Refused,
    ResponseCode::FormErr,
    ResponseCode::NotImp,
    ResponseCode::YXDomain,
    ResponseCode::YXRRSet,
    ResponseCode::NXRRSet,
    ResponseCode::NotAuth,
    ResponseCode::NotZone,
    ResponseCode::BADVERS,
    ResponseCode::BADSIG,
    ResponseCode::BADKEY,
    ResponseCode::BADTIME,
    ResponseCode::BADMODE,
    ResponseCode::BADNAME,
    ResponseCode::BADALG,
    ResponseCode::BADTRUNC,
    ResponseCode::BADCOOKIE,
];

const DEFAULT_NEGATIVE_TTL: Duration = Duration::from_secs(60);

/// How long to wait before asking again about a target that resolved negatively, or
/// `None` when the error must abort the whole SRV resolution.
fn negative_retry_delay(err: &NetError) -> Option<Duration> {
    match err {
        NetError::Dns(DnsError::NoRecordsFound(no_records)) => {
            Some(no_records.negative_ttl.map_or(DEFAULT_NEGATIVE_TTL, |ttl| {
                Duration::from_secs(u64::from(ttl))
            }))
        }
        NetError::Dns(DnsError::ResponseCode(code)) if SERVER_ERROR_RETRY_CODES.contains(code) => {
            Some(DEFAULT_NEGATIVE_TTL)
        }
        _ => None,
    }
}

/// Owner names that the records of this lookup are allowed to have: the name that was
/// asked for, the query's own name (which preserves legitimate canonical cache hits),
/// and every matching-class CNAME target reachable from those in the answer section.
fn selected_owners(lookup: &Lookup, requested: &Name, class: DNSClass) -> HashSet<Name> {
    let mut owners: HashSet<Name> = [requested.clone(), lookup.query().name().clone()]
        .into_iter()
        .collect();
    // The set bounds the walk, so a CNAME cycle cannot loop forever.
    loop {
        let mut added = false;
        for record in lookup.answers() {
            if record.dns_class != class {
                continue;
            }
            let RData::CNAME(target) = &record.data else {
                continue;
            };
            if owners.contains(&record.name) && owners.insert(target.0.clone()) {
                added = true;
            }
        }
        if !added {
            break;
        }
    }
    owners
}

/// Accepted records of `record_type`: matching class, an owner in `owners`, scanned over
/// the answer, authority and additional sections. This replaces the owner/class/type
/// filtering that 0.25's typed lookups performed internally.
fn accepted_records<'a>(
    lookup: &'a Lookup,
    owners: &'a HashSet<Name>,
    class: DNSClass,
    record_type: RecordType,
) -> impl Iterator<Item = &'a Record> + 'a {
    lookup
        .answers()
        .iter()
        .chain(lookup.authorities())
        .chain(lookup.additionals())
        .filter(move |record| {
            record.dns_class == class
                && owners.contains(&record.name)
                && record.record_type() == record_type
        })
}

/// Materialise the addresses of one successful target lookup, honouring the accepted
/// records' TTLs as well as the lookup's own deadline.
fn resolved_target(target: &Name, lookup_ip: LookupIp) -> TargetResolution {
    let query = lookup_ip.query();
    let class = query.query_class();
    // Only the family that was asked for: glue from the other family must not be
    // published, which preserves the old IPv4-first behaviour.
    let record_type = query.query_type();
    let lookup = lookup_ip.as_lookup();
    let owners = selected_owners(lookup, target, class);

    let mut addresses = Vec::new();
    let mut earliest_ttl: Option<Duration> = None;
    for record in accepted_records(lookup, &owners, class, record_type) {
        let Some(address) = record.data.ip_addr() else {
            continue;
        };
        addresses.push(address);
        // 0.26 already clamps and decrements record TTLs; derive the deadline from the
        // accepted records so a short-lived CNAME or address is not hidden by a long one.
        let ttl = Duration::from_secs(u64::from(record.ttl));
        earliest_ttl = Some(earliest_ttl.map_or(ttl, |current| current.min(ttl)));
    }

    let valid_until = match earliest_ttl {
        Some(ttl) => lookup.valid_until().min(Instant::now() + ttl),
        None => lookup.valid_until(),
    };

    TargetResolution::Addresses {
        addresses,
        valid_until,
    }
}

fn endpoint_uri(address: IpAddr, port: u16) -> anyhow::Result<Uri> {
    Uri::builder()
        .scheme(Scheme::HTTPS)
        .path_and_query(PathAndQuery::from_static("/"))
        .authority(format!("{address}:{port}").as_str())
        .build()
        .map_err(anyhow::Error::from)
}

impl Resolver for HickoryResolver {
    async fn resolve_srv(&self, srv: Name) -> anyhow::Result<(HashSet<Uri>, Instant)> {
        // This application, not the resolver cache, decides when the endpoint set is
        // refreshed. Dropping the cache at the start of every application-level
        // resolution keeps an alias entry or an extended-section record from an earlier
        // refresh from outliving the short-lived record that schedules the next one.
        self.0.clear_cache();

        let lookup = self.0.srv_lookup(srv.clone()).await?;

        let query_class = lookup.query().query_class();
        let owners = selected_owners(&lookup, &srv, query_class);
        // One vector drives both the target lookups and the URI generation, so the two
        // passes can never disagree about which ports and targets are published.
        let srv_records: Vec<(Name, u16, Duration)> =
            accepted_records(&lookup, &owners, query_class, RecordType::SRV)
                .filter_map(|record| match &record.data {
                    RData::SRV(data) => Some((
                        data.target.clone(),
                        data.port,
                        Duration::from_secs(u64::from(record.ttl)),
                    )),
                    _ => None,
                })
                .collect();

        // Anchor the SRV-derived deadline to when the SRV response arrived, before any
        // target I/O: a slow target lookup must not extend a short-lived SRV record.
        let mut valid_until = lookup.valid_until();
        for (_, _, ttl) in &srv_records {
            valid_until = valid_until.min(Instant::now() + *ttl);
        }

        let targets: HashSet<Name> = srv_records
            .iter()
            .map(|(target, _, _)| target.clone())
            .collect();

        // Targets are resolved concurrently and share one cache for this resolution.
        let target_resolutions: HashMap<Name, TargetResolution> = targets
            .into_iter()
            .map(|target| async move {
                let resolution = match self.0.lookup_ip(target.clone()).await {
                    Ok(lookup_ip) => resolved_target(&target, lookup_ip),
                    Err(err) => match negative_retry_delay(&err) {
                        Some(delay) => TargetResolution::Negative {
                            valid_until: Instant::now() + delay,
                        },
                        None => return Err(err.into()),
                    },
                };
                Result::<_, anyhow::Error>::Ok((target, resolution))
            })
            .collect::<FuturesUnordered<_>>()
            .try_collect()
            .await?;

        for resolution in target_resolutions.values() {
            valid_until = valid_until.min(resolution.valid_until());
        }

        let mut uris = HashSet::new();
        for (target, port, _) in &srv_records {
            let Some(TargetResolution::Addresses { addresses, .. }) =
                target_resolutions.get(target)
            else {
                continue;
            };
            for address in addresses {
                uris.insert(endpoint_uri(*address, *port)?);
            }
        }

        Ok((uris, valid_until))
    }
}
