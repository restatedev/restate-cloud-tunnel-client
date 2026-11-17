//! Characterisation tests for the SRV discovery contract in `src/srv.rs`.
//!
//! A local TCP nameserver exercises the real resolver, including caching and error
//! classification. Shared behaviour is characterised on 0.25 before the port to 0.26.

use std::{
    collections::{HashMap, HashSet, VecDeque},
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use super::{HickoryResolver, Resolver as _, ServerName, fixed_uri_stream};
use futures::StreamExt;
use hickory_resolver::{
    TokioResolver,
    config::{
        ConnectionConfig, LookupIpStrategy, NameServerConfig, ResolveHosts, ResolverConfig,
        ResolverOpts, ServerOrderingStrategy,
    },
    net::runtime::TokioRuntimeProvider,
    proto::{
        op::{Message, MessageType, ResponseCode},
        rr::{
            DNSClass, Name, RData, Record, RecordType,
            rdata::{A, AAAA, CNAME, SOA, SRV},
        },
    },
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::JoinHandle,
};

const DNS_TIMEOUT: Duration = Duration::from_millis(500);
const IO_TIMEOUT: Duration = Duration::from_secs(2);
const EXPIRY_SLOP: Duration = Duration::from_secs(1);

/// A scripted DNS response for one (name, type) question.
#[derive(Clone, Debug)]
struct Reply {
    rcode: ResponseCode,
    answers: Vec<Record>,
    authority: Vec<Record>,
    additionals: Vec<Record>,
}

impl Reply {
    fn new(rcode: ResponseCode) -> Self {
        Self {
            rcode,
            answers: Vec::new(),
            authority: Vec::new(),
            additionals: Vec::new(),
        }
    }

    fn no_error() -> Self {
        Self::new(ResponseCode::NoError)
    }

    fn answer(mut self, record: Record) -> Self {
        self.answers.push(record);
        self
    }

    fn authority(mut self, record: Record) -> Self {
        self.authority.push(record);
        self
    }

    fn additional(mut self, record: Record) -> Self {
        self.additionals.push(record);
        self
    }
}

#[derive(Clone, Debug)]
enum Action {
    Reply(Reply),
    /// Answer with a real synthetic response, but only after `delay`, so a successful
    /// target lookup can be made to outlast the short-lived record that bounds expiry.
    DelayedReply {
        reply: Reply,
        delay: Duration,
    },
    /// Return a body that is not a DNS message.
    Malformed,
    /// Accept the request and never answer, so the client observes its own timeout.
    Drop,
}

type Key = (String, RecordType);
type Entries = Arc<Mutex<HashMap<Key, Action>>>;

#[derive(Default)]
struct SeenQueries(Mutex<HashSet<(String, RecordType)>>);

impl SeenQueries {
    fn push(&self, name: &str, ty: RecordType) {
        self.0.lock().unwrap().insert((normalize(name), ty));
    }

    fn contains(&self, name: &str, ty: RecordType) -> bool {
        self.0.lock().unwrap().contains(&(normalize(name), ty))
    }
}

struct Fixture {
    addr: SocketAddr,
    dns_timeout: Duration,
    entries: Entries,
    seen: Arc<SeenQueries>,
    listener_task: JoinHandle<()>,
    connection_tasks: Arc<Mutex<Vec<JoinHandle<()>>>>,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.listener_task.abort();
        for task in self.connection_tasks.lock().unwrap().drain(..) {
            task.abort();
        }
    }
}

impl Fixture {
    /// Replace the response for one question at runtime, keeping the same resolver (and
    /// therefore the same cache) across the change.
    fn set(&self, name: &str, ty: RecordType, action: Action) {
        self.entries
            .lock()
            .unwrap()
            .insert((normalize(name), ty), action);
    }

    fn resolver(&self) -> HickoryResolver {
        self.resolver_with_strategy(LookupIpStrategy::Ipv4Only)
    }

    fn resolver_with_strategy(&self, ip_strategy: LookupIpStrategy) -> HickoryResolver {
        self.resolver_with_servers(Some(ip_strategy), &[self.addr])
    }

    fn resolver_with_servers(
        &self,
        ip_strategy: Option<LookupIpStrategy>,
        servers: &[SocketAddr],
    ) -> HickoryResolver {
        let config = ResolverConfig::from_name_servers(
            servers
                .iter()
                .map(|addr| {
                    let mut connection = ConnectionConfig::tcp();
                    connection.port = addr.port();
                    connection.bind_addr = Some(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0));
                    NameServerConfig::new(addr.ip(), true, vec![connection])
                })
                .collect(),
        );

        let mut options = ResolverOpts::default();
        super::preserve_resolver_policy(&mut options);
        options.timeout = self.dns_timeout;
        options.attempts = 1;
        if let Some(ip_strategy) = ip_strategy {
            options.ip_strategy = ip_strategy;
        }
        options.use_hosts_file = ResolveHosts::Never;
        options.edns0 = false;
        options.num_concurrent_reqs = 1;
        options.server_ordering_strategy = ServerOrderingStrategy::UserProvidedOrder;
        options.try_tcp_on_error = false;

        HickoryResolver(
            TokioResolver::builder_with_config(config, TokioRuntimeProvider::default())
                .with_options(options)
                .build()
                .expect("fixture resolver config"),
            Mutex::default(),
        )
    }
}

enum Served {
    Reply(Vec<u8>, Option<Duration>),
    Malformed,
    Drop,
}

fn response_for(entries: &Entries, seen: &SeenQueries, request: &Message) -> Served {
    // 0.26 exposes the query section as a plain vector; this fixture always sends one.
    let Some(query) = request.queries.first() else {
        return Served::Drop;
    };
    let name = normalize(&query.name().to_utf8());
    let ty = query.query_type();
    seen.push(&name, ty);

    // Unspecified questions are an explicit NXDOMAIN, never a silent timeout.
    let action = entries
        .lock()
        .unwrap()
        .get(&(name, ty))
        .cloned()
        .unwrap_or_else(|| Action::Reply(Reply::new(ResponseCode::NXDomain)));
    let (reply, delay) = match action {
        Action::Reply(reply) => (reply, None),
        Action::DelayedReply { reply, delay } => (reply, Some(delay)),
        Action::Malformed => return Served::Malformed,
        Action::Drop => return Served::Drop,
    };

    let mut response = Message::response(request.metadata.id, request.metadata.op_code);
    response.metadata.message_type = MessageType::Response;
    response.metadata.response_code = reply.rcode;
    response.metadata.authoritative = true;
    response.metadata.recursion_available = true;
    response.add_query(query.clone());
    for record in reply.answers {
        response.add_answer(record);
    }
    for record in reply.authority {
        response.add_authority(record);
    }
    for record in reply.additionals {
        response.add_additional(record);
    }
    Served::Reply(response.to_vec().unwrap(), delay)
}

async fn serve_connection(mut stream: TcpStream, entries: Entries, seen: Arc<SeenQueries>) {
    loop {
        let mut len = [0_u8; 2];
        let read_len = tokio::time::timeout(IO_TIMEOUT, stream.read_exact(&mut len)).await;
        if !matches!(read_len, Ok(Ok(_))) {
            break;
        }
        let len = usize::from(u16::from_be_bytes(len));
        let mut buffer = vec![0_u8; len];
        if !matches!(
            tokio::time::timeout(IO_TIMEOUT, stream.read_exact(&mut buffer)).await,
            Ok(Ok(_))
        ) {
            break;
        }
        let Ok(request) = Message::from_vec(&buffer) else {
            continue;
        };
        let response = match response_for(&entries, &seen, &request) {
            Served::Reply(response, delay) => {
                if let Some(delay) = delay {
                    tokio::time::sleep(delay).await;
                }
                response
            }
            // Hold the connection open without answering so the client observes its timeout.
            Served::Drop => continue,
            Served::Malformed => b"not a dns message".to_vec(),
        };
        let response_len = u16::try_from(response.len()).unwrap();
        if !matches!(
            tokio::time::timeout(IO_TIMEOUT, async {
                stream.write_all(&response_len.to_be_bytes()).await?;
                stream.write_all(&response).await
            })
            .await,
            Ok(Ok(()))
        ) {
            break;
        }
    }
}

async fn start_fixture(entries: Vec<(&str, RecordType, Action)>) -> Fixture {
    start_fixture_with_timeout(entries, DNS_TIMEOUT).await
}

async fn start_fixture_with_timeout(
    entries: Vec<(&str, RecordType, Action)>,
    dns_timeout: Duration,
) -> Fixture {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let entries: Entries = Arc::new(Mutex::new(
        entries
            .into_iter()
            .map(|(name, ty, action)| ((normalize(name), ty), action))
            .collect(),
    ));
    let seen = Arc::new(SeenQueries::default());
    let connection_tasks = Arc::new(Mutex::new(Vec::new()));
    let tasks_by_task = Arc::clone(&connection_tasks);
    let seen_by_task = Arc::clone(&seen);
    let entries_by_task = Arc::clone(&entries);

    let listener_task = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let entries = Arc::clone(&entries_by_task);
            let seen = Arc::clone(&seen_by_task);
            let task = tokio::spawn(serve_connection(stream, entries, seen));
            tasks_by_task.lock().unwrap().push(task);
        }
    });

    Fixture {
        addr,
        dns_timeout,
        entries,
        seen,
        listener_task,
        connection_tasks,
    }
}

fn normalize(name: &str) -> String {
    name.trim_end_matches('.').to_ascii_lowercase()
}

fn name(name: &str) -> Name {
    Name::from_utf8(format!("{}.", name.trim_end_matches('.'))).unwrap()
}

fn a(owner: &str, ttl: u32, ip: &str) -> Record {
    Record::from_rdata(
        name(owner),
        ttl,
        RData::A(A::from(ip.parse::<Ipv4Addr>().unwrap())),
    )
}

fn aaaa(owner: &str, ttl: u32, ip: &str) -> Record {
    Record::from_rdata(
        name(owner),
        ttl,
        RData::AAAA(AAAA::from(ip.parse::<Ipv6Addr>().unwrap())),
    )
}

fn cname(owner: &str, ttl: u32, target: &str) -> Record {
    Record::from_rdata(name(owner), ttl, RData::CNAME(CNAME(name(target))))
}

fn srv(owner: &str, ttl: u32, port: u16, target: &str) -> Record {
    Record::from_rdata(
        name(owner),
        ttl,
        RData::SRV(SRV::new(0, 0, port, name(target))),
    )
}

fn soa(zone: &str, ttl: u32, minimum: u32) -> Record {
    Record::from_rdata(
        name(zone),
        ttl,
        RData::SOA(SOA::new(
            name("ns.test"),
            name("hostmaster.test"),
            1,
            3600,
            600,
            86_400,
            minimum,
        )),
    )
}

fn uri_strings(uris: impl IntoIterator<Item = http::Uri>) -> HashSet<String> {
    uris.into_iter().map(|uri| uri.to_string()).collect()
}

fn assert_uris(actual: impl IntoIterator<Item = http::Uri>, expected: &[&str]) {
    let actual = uri_strings(actual);
    let expected: HashSet<String> = expected.iter().map(|uri| uri.to_string()).collect();
    assert_eq!(actual, expected);
}

fn assert_expiry(valid_until: Instant, expected_secs: u64) {
    let remaining = valid_until.saturating_duration_since(Instant::now());
    let expected = Duration::from_secs(expected_secs);
    assert!(
        remaining + EXPIRY_SLOP >= expected && remaining <= expected + EXPIRY_SLOP,
        "expected validity around {expected:?}, got {remaining:?}"
    );
}

/// Every published endpoint must carry the original requested SRV name as its TLS server
/// name, never the IP or the SRV target.
fn assert_server_names(uris: &HashMap<http::Uri, ServerName>, expected: &str) {
    assert!(!uris.is_empty());
    for server_name in uris.values() {
        assert_eq!(
            server_name.to_string().trim_end_matches('.'),
            expected.trim_end_matches('.')
        );
    }
}

async fn resolve(
    fixture: &Fixture,
    srv_name: &str,
) -> anyhow::Result<(HashSet<http::Uri>, Instant)> {
    fixture.resolver().resolve_srv(name(srv_name)).await
}

async fn resolve_with_strategy(
    fixture: &Fixture,
    srv_name: &str,
    strategy: LookupIpStrategy,
) -> anyhow::Result<(HashSet<http::Uri>, Instant)> {
    fixture
        .resolver_with_strategy(strategy)
        .resolve_srv(name(srv_name))
        .await
}

// Each row changes the part of the DNS response that can affect endpoints or expiry.
#[tokio::test]
async fn endpoints_and_deadlines() {
    for (srv_ttl, address_ttl, expected_ttl) in [(3, 30, 3), (30, 2, 2)] {
        let fixture = start_fixture(vec![
            (
                "_svc.test",
                RecordType::SRV,
                Action::Reply(
                    Reply::no_error()
                        .answer(srv("_svc.test", srv_ttl, 8000, "one.test"))
                        .answer(srv("_svc.test", srv_ttl, 8000, "one.test"))
                        .answer(srv("_svc.test", srv_ttl, 8001, "one.test"))
                        .answer(srv("_svc.test", srv_ttl, 8002, "two.test"))
                        .answer(srv("unrelated.test", 300, 9999, "rogue.test"))
                        .additional(srv("unrelated.test", 300, 9998, "rogue.test")),
                ),
            ),
            (
                "one.test",
                RecordType::A,
                Action::Reply(
                    Reply::no_error()
                        .answer(a("one.test", address_ttl, "10.0.0.1"))
                        .answer(a("one.test", address_ttl, "10.0.0.2"))
                        .answer(a("unrelated.test", 300, "10.0.0.99")),
                ),
            ),
            (
                "two.test",
                RecordType::A,
                Action::Reply(Reply::no_error().answer(a("two.test", address_ttl, "10.0.0.3"))),
            ),
        ])
        .await;
        let (uris, expiry) = resolve(&fixture, "_svc.test").await.unwrap();
        assert_uris(
            uris,
            &[
                "https://10.0.0.1:8000/",
                "https://10.0.0.2:8000/",
                "https://10.0.0.1:8001/",
                "https://10.0.0.2:8001/",
                "https://10.0.0.3:8002/",
            ],
        );
        assert_expiry(expiry, expected_ttl);
        assert!(!fixture.seen.contains("rogue.test", RecordType::A));
    }
}

#[tokio::test]
async fn aliases_and_record_sections() {
    // The SRV owner and its address may both be aliases. Canonical records can
    // occur outside the answer section; unrelated owners must still be ignored.
    for additional in [false, true] {
        let canonical_ip = a("real.test", 7, "10.0.0.9");
        let mut service = Reply::no_error();
        let mut address = Reply::no_error()
            .answer(cname("alias.test", 5, "real.test"))
            .answer(a("unrelated.test", 300, "10.0.0.99"));
        if additional {
            service = service
                .answer(cname("_svc.test", 5, "_canonical.test"))
                .additional(srv("_canonical.test", 20, 8443, "alias.test"));
            address = address.additional(canonical_ip);
        } else {
            service = service.answer(srv("_svc.test", 20, 8443, "alias.test"));
            address = address.answer(canonical_ip);
        }
        let fixture = start_fixture(vec![
            ("_svc.test", RecordType::SRV, Action::Reply(service)),
            ("alias.test", RecordType::A, Action::Reply(address)),
        ])
        .await;
        let (uris, expiry) = resolve(&fixture, "_svc.test").await.unwrap();
        assert_uris(uris, &["https://10.0.0.9:8443/"]);
        assert_expiry(expiry, 5);
    }
    // Matching SRVs in authority and additional sections contribute both ports
    // and TTLs, even when the answer itself remains valid much longer.
    let fixture = start_fixture(vec![
        (
            "_svc.test",
            RecordType::SRV,
            Action::Reply(
                Reply::no_error()
                    .answer(srv("_svc.test", 300, 8500, "target.test"))
                    .authority(srv("_svc.test", 3, 8501, "target.test"))
                    .additional(srv("_svc.test", 2, 8502, "target.test")),
            ),
        ),
        (
            "target.test",
            RecordType::A,
            Action::Reply(Reply::no_error().answer(a("target.test", 300, "10.0.0.9"))),
        ),
    ])
    .await;
    let (uris, expiry) = resolve(&fixture, "_svc.test").await.unwrap();
    assert_uris(
        uris,
        &[
            "https://10.0.0.9:8500/",
            "https://10.0.0.9:8501/",
            "https://10.0.0.9:8502/",
        ],
    );
    assert_expiry(expiry, 2);
}

#[tokio::test]
async fn negative_targets_use_soa_or_fallback() {
    for rcode in [ResponseCode::NXDomain, ResponseCode::NoError] {
        for (soa_ttls, expected) in [(None, 60), (Some((2, 9)), 2), (Some((9, 3)), 3)] {
            for healthy in [false, true] {
                let mut negative = Reply::new(rcode);
                if let Some((ttl, minimum)) = soa_ttls {
                    negative = negative.authority(soa("test", ttl, minimum));
                }
                let fixture = target_fixture(Action::Reply(negative), healthy, false).await;
                let (uris, expiry) = resolve(&fixture, "_svc.test").await.unwrap();
                assert_healthy(uris, healthy);
                assert_expiry(expiry, expected);
            }
        }
    }
}

// One shared setup for target failures: a long-lived healthy endpoint cannot
// hide a negative TTL or turn a transport failure into a partial success.
async fn target_fixture(action: Action, healthy: bool, both_families: bool) -> Fixture {
    let mut service = Reply::no_error().answer(srv("_svc.test", 300, 8444, "failed.test"));
    if healthy {
        service = service.answer(srv("_svc.test", 300, 8443, "healthy.test"));
    }
    let mut entries = vec![
        ("_svc.test", RecordType::SRV, Action::Reply(service)),
        (
            "healthy.test",
            RecordType::A,
            Action::Reply(Reply::no_error().answer(a("healthy.test", 120, "10.0.6.1"))),
        ),
        ("failed.test", RecordType::A, action.clone()),
    ];
    if both_families {
        entries.push(("failed.test", RecordType::AAAA, action));
    }
    start_fixture(entries).await
}

fn assert_healthy(uris: HashSet<http::Uri>, healthy: bool) {
    assert_uris(
        uris,
        if healthy {
            &["https://10.0.6.1:8443/"]
        } else {
            &[]
        },
    );
}

#[tokio::test]
async fn target_server_errors_are_negative() {
    // Extended response codes need an EDNS OPT record and are not wire-tested.
    for rcode in [
        ResponseCode::ServFail,
        ResponseCode::Refused,
        ResponseCode::FormErr,
        ResponseCode::NotImp,
        ResponseCode::YXDomain,
        ResponseCode::YXRRSet,
        ResponseCode::NXRRSet,
        ResponseCode::NotAuth,
        ResponseCode::NotZone,
    ] {
        for healthy in [false, true] {
            let fixture = target_fixture(Action::Reply(Reply::new(rcode)), healthy, true).await;
            let (uris, expiry) =
                resolve_with_strategy(&fixture, "_svc.test", LookupIpStrategy::Ipv4thenIpv6)
                    .await
                    .unwrap();
            assert_healthy(uris, healthy);
            assert_expiry(expiry, 60);
            assert!(
                fixture.seen.contains("failed.test", RecordType::A),
                "{rcode:?}"
            );
            assert!(
                fixture.seen.contains("failed.test", RecordType::AAAA),
                "{rcode:?}"
            );
        }
    }
}

#[tokio::test]
async fn target_transport_errors_abort() {
    for action in [Action::Malformed, Action::Drop] {
        for strategy in [LookupIpStrategy::Ipv4Only, LookupIpStrategy::Ipv4thenIpv6] {
            let fixture = target_fixture(action.clone(), true, true).await;
            assert!(
                resolve_with_strategy(&fixture, "_svc.test", strategy)
                    .await
                    .is_err(),
                "{action:?}, {strategy:?}"
            );
            assert!(fixture.seen.contains("failed.test", RecordType::A));
            if strategy == LookupIpStrategy::Ipv4thenIpv6 {
                assert!(fixture.seen.contains("failed.test", RecordType::AAAA));
            }
        }
    }
}

#[tokio::test]
async fn target_a_transport_failure_can_end_as_negative() {
    for action in [Action::Malformed, Action::Drop] {
        let fixture = target_fixture(action, true, false).await;
        let (uris, expiry) =
            resolve_with_strategy(&fixture, "_svc.test", LookupIpStrategy::Ipv4thenIpv6)
                .await
                .unwrap();
        assert_healthy(uris, true);
        assert_expiry(expiry, 60);
        assert!(fixture.seen.contains("failed.test", RecordType::A));
        assert!(fixture.seen.contains("failed.test", RecordType::AAAA));
    }
}

#[tokio::test]
async fn target_server_errors_preserve_previous_endpoints() {
    for negative in [
        Reply::new(ResponseCode::NXDomain),
        Reply::no_error(),
        Reply::new(ResponseCode::NXDomain).authority(soa("test", 8, 3)),
        Reply::no_error().authority(soa("test", 8, 3)),
    ] {
        let good = Action::Reply(Reply::no_error().answer(a("failed.test", 120, "10.0.6.2")));
        let bad = target_fixture(good.clone(), true, false).await;
        let healthy = target_fixture(good, true, false).await;
        let resolver = bad.resolver_with_servers(None, &[bad.addr, healthy.addr]);
        let expected = ["https://10.0.6.1:8443/", "https://10.0.6.2:8444/"];
        assert_uris(
            resolver.resolve_srv(name("_svc.test")).await.unwrap().0,
            &expected,
        );
        // The other TCP server can still answer the target successfully.
        assert_uris(resolve(&healthy, "_svc.test").await.unwrap().0, &expected);
        for ty in [RecordType::A, RecordType::AAAA] {
            bad.set(
                "failed.test",
                ty,
                Action::Reply(Reply::new(ResponseCode::ServFail)),
            );
        }
        for _ in 0..2 {
            let (uris, expiry) = resolver.resolve_srv(name("_svc.test")).await.unwrap();
            assert_uris(uris, &expected);
            assert_expiry(expiry, 60);
        }
        // A genuine negative must remove the saved endpoints, with or without SOA.
        for ty in [RecordType::A, RecordType::AAAA] {
            bad.set("failed.test", ty, Action::Reply(negative.clone()));
        }
        assert_healthy(
            resolver.resolve_srv(name("_svc.test")).await.unwrap().0,
            true,
        );
        for ty in [RecordType::A, RecordType::AAAA] {
            bad.set(
                "failed.test",
                ty,
                Action::Reply(Reply::new(ResponseCode::ServFail)),
            );
        }
        assert_healthy(
            resolver.resolve_srv(name("_svc.test")).await.unwrap().0,
            true,
        );
    }
}

#[tokio::test]
async fn zero_ttl_refreshes_wait_before_querying_again() {
    for (srv_ttl, address_ttl, negative) in [(0, 120, false), (120, 0, false), (120, 120, true)] {
        let fixture = target_fixture(
            Action::Reply(if negative {
                Reply::new(ResponseCode::NXDomain).authority(soa("test", 120, 0))
            } else {
                Reply::no_error().answer(a("failed.test", address_ttl, "10.0.6.2"))
            }),
            false,
            false,
        )
        .await;
        fixture.set(
            "_svc.test",
            RecordType::SRV,
            Action::Reply(Reply::no_error().answer(srv("_svc.test", srv_ttl, 8444, "failed.test"))),
        );
        let mut updates = Box::pin(fixture.resolver().into_stream(name("_svc.test")));
        updates.next().await.unwrap();
        let started = Instant::now();
        assert!(
            tokio::time::timeout(Duration::from_millis(200), updates.next())
                .await
                .is_err(),
            "zero TTL caused immediate refresh"
        );
        tokio::time::timeout(Duration::from_secs(2), updates.next())
            .await
            .expect("refresh after floor")
            .unwrap();
        assert!(started.elapsed() >= Duration::from_secs(1));
    }
}

#[tokio::test]
async fn srv_failures_propagate() {
    for action in [
        Action::Reply(Reply::new(ResponseCode::NXDomain)),
        Action::Reply(Reply::no_error().authority(soa("test", 4, 8))),
        Action::Reply(Reply::new(ResponseCode::ServFail)),
        Action::Malformed,
        Action::Drop,
    ] {
        let fixture = start_fixture(vec![("_svc.test", RecordType::SRV, action.clone())]).await;
        assert!(resolve(&fixture, "_svc.test").await.is_err(), "{action:?}");
        assert!(fixture.seen.contains("_svc.test", RecordType::SRV));
    }
}
#[tokio::test]
async fn ipv4_policy_ignores_other_family_glue() {
    let fixture = start_fixture(vec![
        (
            "_svc.dual.test",
            RecordType::SRV,
            Action::Reply(Reply::no_error().answer(srv("_svc.dual.test", 20, 8443, "dual.test"))),
        ),
        (
            "dual.test",
            RecordType::A,
            Action::Reply(
                Reply::no_error()
                    .answer(a("dual.test", 30, "10.0.5.1"))
                    .additional(aaaa("dual.test", 40, "2001:db8::1")),
            ),
        ),
        (
            "dual.test",
            RecordType::AAAA,
            Action::Reply(Reply::no_error().answer(aaaa("dual.test", 40, "2001:db8::1"))),
        ),
    ])
    .await;

    let (uris, valid_until) = fixture
        .resolver_with_servers(None, &[fixture.addr])
        .resolve_srv(name("_svc.dual.test"))
        .await
        .unwrap();
    // The AAAA glue in the same reply must not be published, and the SRV TTL is the
    // earliest relevant record.
    assert_uris(uris, &["https://10.0.5.1:8443/"]);
    assert_expiry(valid_until, 20);

    // Fallback row: A is negative, so the old policy asks AAAA and receives an IPv6
    // address. Publishing it fails in the existing (unbracketed) URI construction;
    // this characterises today's behaviour, not a new IPv6 feature.
    let fixture = start_fixture(vec![
        (
            "_svc.v6.test",
            RecordType::SRV,
            Action::Reply(Reply::no_error().answer(srv("_svc.v6.test", 20, 8445, "v6only.test"))),
        ),
        (
            "v6only.test",
            RecordType::A,
            Action::Reply(Reply::new(ResponseCode::NXDomain)),
        ),
        (
            "v6only.test",
            RecordType::AAAA,
            Action::Reply(Reply::no_error().answer(aaaa("v6only.test", 30, "2001:db8::2"))),
        ),
    ])
    .await;

    assert!(
        fixture
            .resolver_with_servers(None, &[fixture.addr])
            .resolve_srv(name("_svc.v6.test"))
            .await
            .is_err(),
        "IPv6-only endpoints fail in the existing URI construction"
    );
    assert!(fixture.seen.contains("v6only.test", RecordType::AAAA));
}

type ScriptedStep = anyhow::Result<(HashSet<http::Uri>, Instant)>;

struct ScriptedResolver {
    script: Arc<Mutex<VecDeque<ScriptedStep>>>,
}

impl ScriptedResolver {
    fn new(script: Vec<ScriptedStep>) -> Self {
        Self {
            script: Arc::new(Mutex::new(script.into())),
        }
    }
}

impl super::Resolver for ScriptedResolver {
    async fn resolve_srv(&self, _srv: Name) -> anyhow::Result<(HashSet<http::Uri>, Instant)> {
        let next = self.script.lock().unwrap().pop_front();
        match next {
            Some(next) => next,
            None => std::future::pending().await,
        }
    }
}

#[tokio::test]
async fn srv_stream_errors_preserve_previous_update() {
    let first_uri = http::Uri::from_static("https://10.0.11.1:4430/");
    let second_uri = http::Uri::from_static("https://10.0.11.2:4430/");
    let resolver = ScriptedResolver::new(vec![
        // The first update is immediately due again, so the scripted error follows at once.
        Ok((HashSet::from([first_uri.clone()]), Instant::now())),
        Err(anyhow::anyhow!("scripted resolution failure")),
        Ok((
            HashSet::from([second_uri.clone()]),
            Instant::now() + Duration::from_secs(3600),
        )),
    ]);

    let mut updates = Box::pin(resolver.into_stream(name("_svc.stream.test")));
    let first = updates.next().await.expect("first update");
    assert_eq!(uri_strings(first.keys().cloned()), uri_strings([first_uri]));
    assert_server_names(&first, "_svc.stream.test");

    let started = Instant::now();
    // The error must not replace the current endpoints with an empty map, and the
    // retry must wait the documented five seconds.
    let second = tokio::time::timeout(Duration::from_secs(8), updates.next())
        .await
        .expect("an update after the scripted error")
        .expect("stream update");
    let elapsed = started.elapsed();
    assert_eq!(
        uri_strings(second.keys().cloned()),
        uri_strings([second_uri])
    );
    assert!(
        elapsed >= Duration::from_millis(4_900),
        "retry after an error must wait about five seconds, waited {elapsed:?}"
    );
    assert!(elapsed <= Duration::from_secs(7), "retry took {elapsed:?}");

    // The successful update schedules the next refresh from its own deadline.
    assert!(
        tokio::time::timeout(Duration::from_millis(100), updates.next())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn discovery_expiry_is_anchored_to_the_srv_response() {
    let fixture = start_fixture_with_timeout(
        vec![
            (
                "_svc.delay.test",
                RecordType::SRV,
                Action::Reply(
                    Reply::no_error()
                        .answer(srv("_svc.delay.test", 300, 8600, "anchored.test"))
                        // The short matching additional record bounds expiry.
                        .additional(srv("_svc.delay.test", 2, 8601, "anchored.test")),
                ),
            ),
            (
                "anchored.test",
                RecordType::A,
                Action::DelayedReply {
                    reply: Reply::no_error().answer(a("anchored.test", 120, "10.0.12.1")),
                    delay: Duration::from_secs(1),
                },
            ),
        ],
        Duration::from_millis(1_500),
    )
    .await;

    let started = Instant::now();
    let (uris, valid_until) = resolve(&fixture, "_svc.delay.test").await.unwrap();
    let elapsed = started.elapsed();

    assert_uris(
        uris,
        &["https://10.0.12.1:8600/", "https://10.0.12.1:8601/"],
    );
    assert!(
        elapsed >= Duration::from_millis(800),
        "the address response must have been delayed, took {elapsed:?}"
    );
    assert!(fixture.seen.contains("anchored.test", RecordType::A));

    // The two-second additional SRV TTL is measured from when the SRV response arrived,
    // so a slow target lookup must not extend it by the lookup latency.
    let from_start = valid_until.saturating_duration_since(started);
    assert!(
        from_start <= Duration::from_millis(2_400),
        "a slow target lookup extended the SRV-derived validity: {from_start:?} from the start"
    );
    assert!(
        from_start + Duration::from_millis(200) >= Duration::from_secs(2),
        "the accepted additional SRV must still bound validity: {from_start:?} from the start"
    );
}

#[tokio::test]
async fn extra_section_expiry_refreshes_endpoints_without_spin() {
    let fixture = start_fixture(vec![
        (
            "_svc.extra.test",
            RecordType::SRV,
            Action::Reply(
                Reply::no_error()
                    .answer(srv("_svc.extra.test", 300, 8500, "extra.test"))
                    .additional(srv("_svc.extra.test", 2, 8501, "extra.test")),
            ),
        ),
        (
            "extra.test",
            RecordType::A,
            Action::Reply(Reply::no_error().answer(a("extra.test", 120, "10.0.7.1"))),
        ),
    ])
    .await;

    let mut updates = Box::pin(fixture.resolver().into_stream(name("_svc.extra.test")));
    let first = updates.next().await.expect("first update");
    assert_eq!(
        uri_strings(first.keys().cloned()),
        uri_strings([
            http::Uri::from_static("https://10.0.7.1:8500/"),
            http::Uri::from_static("https://10.0.7.1:8501/"),
        ])
    );
    assert_server_names(&first, "_svc.extra.test");

    // Publish the change immediately after the first update; the next refresh is
    // scheduled by the two-second additional SRV.
    fixture.set(
        "_svc.extra.test",
        RecordType::SRV,
        Action::Reply(Reply::no_error().answer(srv("_svc.extra.test", 300, 8500, "extra.test"))),
    );

    let second = tokio::time::timeout(Duration::from_secs(4), updates.next())
        .await
        .expect("the expired additional SRV must trigger a refresh")
        .expect("stream update");
    assert_eq!(
        uri_strings(second.keys().cloned()),
        uri_strings([http::Uri::from_static("https://10.0.7.1:8500/")]),
        "the endpoint from the expired additional SRV must disappear"
    );

    // An expired extra-section record must not leave the stream spinning.
    assert!(
        tokio::time::timeout(Duration::from_millis(100), updates.next())
            .await
            .is_err(),
        "expired additional records must not cause an immediate refresh loop"
    );
}

#[tokio::test]
async fn alias_changes_are_observed_during_shorter_target_refresh() {
    let fixture = start_fixture(vec![
        (
            "_svc.alias.test",
            RecordType::SRV,
            Action::Reply(
                Reply::no_error()
                    .answer(srv("_svc.alias.test", 300, 4430, "alias.test"))
                    .answer(srv("_svc.alias.test", 300, 8443, "stable.test")),
            ),
        ),
        // The alias answer is CNAME-only: the canonical address is a separate query, so
        // the priming call below seeds the same cache entry an alias lookup would create.
        (
            "alias.test",
            RecordType::A,
            Action::Reply(Reply::no_error().answer(cname("alias.test", 5, "real1.test"))),
        ),
        (
            "real1.test",
            RecordType::A,
            Action::Reply(Reply::no_error().answer(a("real1.test", 60, "10.0.9.1"))),
        ),
        (
            "stable.test",
            RecordType::A,
            Action::Reply(Reply::no_error().answer(a("stable.test", 2, "10.0.9.2"))),
        ),
        (
            "real2.test",
            RecordType::A,
            Action::Reply(Reply::no_error().answer(a("real2.test", 60, "10.0.9.3"))),
        ),
    ])
    .await;

    let resolver = fixture.resolver();
    // Prime the canonical address through this resolver, as an earlier alias lookup would.
    resolver
        .0
        .lookup_ip(name("real1.test"))
        .await
        .expect("priming the canonical address");
    let mut updates = Box::pin(resolver.into_stream(name("_svc.alias.test")));
    let first = updates.next().await.expect("first update");
    assert_eq!(
        uri_strings(first.keys().cloned()),
        uri_strings([
            http::Uri::from_static("https://10.0.9.1:4430/"),
            http::Uri::from_static("https://10.0.9.2:8443/"),
        ])
    );

    // Wait past the alias CNAME TTL, then repoint the alias at a different address.
    tokio::time::sleep(Duration::from_millis(5_500)).await;
    fixture.set(
        "alias.test",
        RecordType::A,
        Action::Reply(Reply::no_error().answer(cname("alias.test", 60, "real2.test"))),
    );

    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        assert!(
            remaining > Duration::from_millis(200),
            "the alias endpoint never moved to the new canonical address"
        );
        let update = tokio::time::timeout(remaining, updates.next())
            .await
            .expect("an update while the alias change is pending")
            .expect("stream update");
        let uris = uri_strings(update.keys().cloned());
        if uris.contains("https://10.0.9.3:4430/") {
            assert!(
                !uris.contains("https://10.0.9.1:4430/"),
                "the old alias endpoint must disappear when the alias changes"
            );
            assert!(uris.contains("https://10.0.9.2:8443/"));
            break;
        }
    }
}

#[tokio::test]
async fn fixed_uri_stream_is_stable() {
    let uris: HashMap<http::Uri, ServerName> = HashMap::from([
        (
            http::Uri::from_static("https://127.0.0.1:19080/"),
            "server-one.example.com".parse().unwrap(),
        ),
        (
            http::Uri::from_static("https://127.0.0.2:19080/"),
            "server-two.example.com".parse().unwrap(),
        ),
    ]);

    let mut updates = Box::pin(fixed_uri_stream(uris.clone()));
    let first = updates.next().await.expect("one configured update");
    assert_uris(
        first.keys().cloned(),
        &["https://127.0.0.1:19080/", "https://127.0.0.2:19080/"],
    );
    assert_eq!(
        first[&http::Uri::from_static("https://127.0.0.1:19080/")].to_string(),
        "server-one.example.com"
    );
    assert_eq!(
        first[&http::Uri::from_static("https://127.0.0.2:19080/")].to_string(),
        "server-two.example.com"
    );

    assert!(
        tokio::time::timeout(Duration::from_millis(100), updates.next())
            .await
            .is_err(),
        "a fixed endpoint map is published once and then stays pending"
    );
}

// 0.26 rejects foreign-class responses before the client's owner filtering.
#[tokio::test]
async fn foreign_class_responses_fail() {
    for target in [false, true] {
        let fixture = target_fixture(
            Action::Reply(Reply::no_error().answer(a("failed.test", 30, "10.0.0.1"))),
            true,
            false,
        )
        .await;
        if target {
            let mut foreign = a("failed.test", 30, "10.0.0.99");
            foreign.dns_class = DNSClass::CH;
            fixture.set(
                "failed.test",
                RecordType::A,
                Action::Reply(
                    Reply::no_error()
                        .answer(a("failed.test", 30, "10.0.0.1"))
                        .answer(foreign),
                ),
            );
        } else {
            let mut foreign = srv("_svc.test", 30, 9999, "healthy.test");
            foreign.dns_class = DNSClass::CH;
            fixture.set(
                "_svc.test",
                RecordType::SRV,
                Action::Reply(
                    Reply::no_error()
                        .answer(srv("_svc.test", 30, 8443, "healthy.test"))
                        .answer(foreign),
                ),
            );
        }
        // Both replies otherwise contain usable endpoints. Error cannot be
        // explained by missing data, and no dependency error variant is pinned.
        assert!(resolve(&fixture, "_svc.test").await.is_err());
        assert!(fixture.seen.contains(
            if target { "failed.test" } else { "_svc.test" },
            if target {
                RecordType::A
            } else {
                RecordType::SRV
            }
        ));
    }
}

#[tokio::test]
async fn production_constructor_preserves_resolver_policy() {
    let resolver = HickoryResolver::new();
    let options = resolver.0.options();
    assert_eq!(options.ip_strategy, LookupIpStrategy::Ipv4thenIpv6);
    assert_eq!(options.cache_size, 32);
    assert_eq!(options.max_active_requests, 33);
    // Linux inherits resolv.conf; Windows and Apple retain disabled EDNS.
    #[cfg(any(windows, target_vendor = "apple"))]
    assert!(!options.edns0);
}
