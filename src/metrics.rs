use prometheus::{
    Encoder, IntCounterVec, IntGaugeVec, Opts, Registry, TextEncoder,
    core::{AtomicI64, AtomicU64, GenericCounter, GenericGauge},
};
use std::sync::LazyLock;

pub struct Metrics {
    registry: Registry,
    opened: IntGaugeVec,
    draining: IntGaugeVec,
    connection_attempts: IntCounterVec,
    local_proxy_requests: IntCounterVec,
    remote_proxy_requests: IntCounterVec,
}

/// Metrics scoped to a particular tunnel server
#[derive(Clone)]
pub struct TunnelMetrics {
    opened: GenericGauge<AtomicI64>,
    draining: GenericGauge<AtomicI64>,
    connection_attempts: GenericCounter<AtomicU64>,
}

impl TunnelMetrics {
    pub fn opened(&self, value: bool) {
        self.opened.set(if value { 1 } else { 0 });
    }

    pub fn draining(&self, value: bool) {
        self.draining.set(if value { 1 } else { 0 });
    }

    pub fn inc_connection_attempts(&self) {
        self.connection_attempts.inc();
    }
}

impl Metrics {
    fn new() -> Self {
        let registry = Registry::new();

        let opened = IntGaugeVec::new(
            Opts::new(
                "opened",
                "Whether the tunnel is currently open (1) or not (0)",
            )
            .namespace("restate_cloud_tunnel"),
            &["server"],
        )
        .expect("metric can be created");
        registry
            .register(Box::new(opened.clone()))
            .expect("metric can be registered");

        let draining = IntGaugeVec::new(
            Opts::new(
                "draining",
                "Whether the tunnel is currently draining (1) or not (0)",
            )
            .namespace("restate_cloud_tunnel"),
            &["server"],
        )
        .expect("metric can be created");
        registry
            .register(Box::new(draining.clone()))
            .expect("metric can be registered");

        let connection_attempts = IntCounterVec::new(
            Opts::new(
                "connection_attempts_total",
                "Total number of tunnel connection attempts",
            )
            .namespace("restate_cloud_tunnel"),
            &["server"],
        )
        .expect("metric can be created");
        registry
            .register(Box::new(connection_attempts.clone()))
            .expect("metric can be registered");

        let local_proxy_requests = IntCounterVec::new(
            Opts::new(
                "local_proxy_requests_total",
                "Total requests proxied from Restate Cloud to local services",
            )
            .namespace("restate_cloud_tunnel"),
            &["status"],
        )
        .expect("metric can be created");
        registry
            .register(Box::new(local_proxy_requests.clone()))
            .expect("metric can be registered");

        let remote_proxy_requests = IntCounterVec::new(
            Opts::new(
                "remote_proxy_requests_total",
                "Total requests proxied from local network to Restate Cloud",
            )
            .namespace("restate_cloud_tunnel"),
            &["status"],
        )
        .expect("metric can be created");
        registry
            .register(Box::new(remote_proxy_requests.clone()))
            .expect("metric can be registered");

        Self {
            registry,
            opened,
            draining,
            connection_attempts,
            local_proxy_requests,
            remote_proxy_requests,
        }
    }

    /// Render all metrics in Prometheus text format
    pub fn render(&self) -> String {
        let encoder = TextEncoder::new();
        let metric_families = self.registry.gather();
        let mut buffer = Vec::new();
        encoder
            .encode(&metric_families, &mut buffer)
            .expect("encoding should succeed");
        String::from_utf8(buffer).expect("metrics should be valid UTF-8")
    }

    /// Create metrics scoped to a particular tunnel server
    pub fn tunnel(&self, server: &str) -> TunnelMetrics {
        TunnelMetrics {
            opened: self.opened.with_label_values(&[server]),
            draining: self.draining.with_label_values(&[server]),
            connection_attempts: self.connection_attempts.with_label_values(&[server]),
        }
    }

    pub fn remove_tunnel(&self, server: &str) {
        let _ = self.opened.remove_label_values(&[server]);
        let _ = self.draining.remove_label_values(&[server]);
        // we keep labels in connection_attempts as it is a counter, this is a theoretical cardinality issue
        // but in practice tunnel server ips do not change much
    }

    pub fn record_local_proxy_request(&self, success: bool) {
        self.local_proxy_requests
            .with_label_values(&[if success { "success" } else { "error" }])
            .inc();
    }

    pub fn record_remote_proxy_request(&self, success: bool) {
        self.remote_proxy_requests
            .with_label_values(&[if success { "success" } else { "error" }])
            .inc();
    }
}

pub static METRICS: LazyLock<Metrics> = LazyLock::new(Metrics::new);
