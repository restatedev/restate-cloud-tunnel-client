use prometheus::{
    Encoder, Histogram, HistogramOpts, HistogramVec, IntCounterVec, IntGaugeVec, Opts, Registry,
    TextEncoder,
    core::{AtomicI64, AtomicU64, GenericCounter, GenericGauge},
};
use std::{
    sync::LazyLock,
    time::{Duration, Instant},
};

const REQUEST_DURATION_BUCKETS: &[f64] = &[
    0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0,
];

pub struct Metrics {
    registry: Registry,
    opened: IntGaugeVec,
    draining: IntGaugeVec,
    connection_attempts: IntCounterVec,
    requests: IntCounterVec,
    request_duration: HistogramVec,
    requests_inflight: IntGaugeVec,
    local_handler_duration: HistogramVec,
    local_handler_inflight: IntGaugeVec,
    local_proxy_requests: IntCounterVec,
    remote_proxy_requests: IntCounterVec,
}

/// Metrics scoped to a particular tunnel server
#[derive(Clone)]
pub struct TunnelMetrics {
    opened: GenericGauge<AtomicI64>,
    draining: GenericGauge<AtomicI64>,
    connection_attempts: GenericCounter<AtomicU64>,
    request_metrics: RequestMetrics,
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

    pub fn start_request(&self) -> RequestGuard {
        self.request_metrics.start()
    }
}

#[derive(Clone)]
pub struct RequestMetrics {
    inflight: GenericGauge<AtomicI64>,
    duration: Histogram,
    ok: GenericCounter<AtomicU64>,
    error: GenericCounter<AtomicU64>,
}

impl RequestMetrics {
    pub fn start(&self) -> RequestGuard {
        self.inflight.inc();
        RequestGuard {
            inflight: self.inflight.clone(),
            duration: self.duration.clone(),
            ok: self.ok.clone(),
            error: self.error.clone(),
            start: Instant::now(),
            finished: false,
        }
    }
}

pub struct RequestGuard {
    inflight: GenericGauge<AtomicI64>,
    duration: Histogram,
    ok: GenericCounter<AtomicU64>,
    error: GenericCounter<AtomicU64>,
    start: Instant,
    finished: bool,
}

impl RequestGuard {
    pub fn finish(mut self, success: bool) {
        self.observe(success);
    }

    fn observe(&mut self, success: bool) {
        if self.finished {
            return;
        }

        self.duration.observe(elapsed_seconds(self.start.elapsed()));
        if success {
            self.ok.inc();
        } else {
            self.error.inc();
        }
        self.inflight.dec();
        self.finished = true;
    }
}

impl Drop for RequestGuard {
    fn drop(&mut self) {
        if !self.finished {
            self.inflight.dec();
        }
    }
}

#[derive(Clone)]
pub struct LocalHandlerMetrics {
    inflight: GenericGauge<AtomicI64>,
    duration: Histogram,
}

impl LocalHandlerMetrics {
    pub fn start(&self) -> LocalHandlerGuard {
        self.inflight.inc();
        LocalHandlerGuard {
            inflight: self.inflight.clone(),
            duration: self.duration.clone(),
            start: Instant::now(),
            finished: false,
        }
    }
}

pub struct LocalHandlerGuard {
    inflight: GenericGauge<AtomicI64>,
    duration: Histogram,
    start: Instant,
    finished: bool,
}

impl LocalHandlerGuard {
    pub fn finish(mut self) {
        if self.finished {
            return;
        }

        self.duration.observe(elapsed_seconds(self.start.elapsed()));
        self.inflight.dec();
        self.finished = true;
    }
}

impl Drop for LocalHandlerGuard {
    fn drop(&mut self) {
        if !self.finished {
            self.inflight.dec();
        }
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
            &["server", "connection"],
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
            &["server", "connection"],
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
            &["server", "connection"],
        )
        .expect("metric can be created");
        registry
            .register(Box::new(connection_attempts.clone()))
            .expect("metric can be registered");

        let requests = IntCounterVec::new(
            Opts::new(
                "requests_total",
                "Total requests proxied by the tunnel client",
            )
            .namespace("restate_cloud_tunnel"),
            &["server", "connection", "direction", "status"],
        )
        .expect("metric can be created");
        registry
            .register(Box::new(requests.clone()))
            .expect("metric can be registered");

        let request_duration = HistogramVec::new(
            HistogramOpts::new(
                "request_duration_seconds",
                "Time from tunnel-client request handling to upstream response headers",
            )
            .namespace("restate_cloud_tunnel")
            .buckets(REQUEST_DURATION_BUCKETS.to_vec()),
            &["server", "connection", "direction"],
        )
        .expect("metric can be created");
        registry
            .register(Box::new(request_duration.clone()))
            .expect("metric can be registered");

        let requests_inflight = IntGaugeVec::new(
            Opts::new(
                "requests_inflight",
                "Requests currently being handled by the tunnel client",
            )
            .namespace("restate_cloud_tunnel"),
            &["server", "connection", "direction"],
        )
        .expect("metric can be created");
        registry
            .register(Box::new(requests_inflight.clone()))
            .expect("metric can be registered");

        let local_handler_duration = HistogramVec::new(
            HistogramOpts::new(
                "local_handler_duration_seconds",
                "Time from forwarding to a local handler until response headers are received",
            )
            .namespace("restate_cloud_tunnel")
            .buckets(REQUEST_DURATION_BUCKETS.to_vec()),
            &["instance"],
        )
        .expect("metric can be created");
        registry
            .register(Box::new(local_handler_duration.clone()))
            .expect("metric can be registered");

        let local_handler_inflight = IntGaugeVec::new(
            Opts::new(
                "local_handler_inflight",
                "Requests currently waiting on a local handler response",
            )
            .namespace("restate_cloud_tunnel"),
            &["instance"],
        )
        .expect("metric can be created");
        registry
            .register(Box::new(local_handler_inflight.clone()))
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
            requests,
            request_duration,
            requests_inflight,
            local_handler_duration,
            local_handler_inflight,
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
    pub fn tunnel(&self, server: &str, connection_index: usize) -> TunnelMetrics {
        let connection_index = connection_index.to_string();

        TunnelMetrics {
            opened: self
                .opened
                .with_label_values(&[server, connection_index.as_str()]),
            draining: self
                .draining
                .with_label_values(&[server, connection_index.as_str()]),
            connection_attempts: self
                .connection_attempts
                .with_label_values(&[server, connection_index.as_str()]),
            request_metrics: self.request(server, connection_index.as_str(), "inbound"),
        }
    }

    pub fn request(&self, server: &str, connection: &str, direction: &str) -> RequestMetrics {
        RequestMetrics {
            inflight: self
                .requests_inflight
                .with_label_values(&[server, connection, direction]),
            duration: self
                .request_duration
                .with_label_values(&[server, connection, direction]),
            ok: self
                .requests
                .with_label_values(&[server, connection, direction, "ok"]),
            error: self
                .requests
                .with_label_values(&[server, connection, direction, "error"]),
        }
    }

    pub fn local_handler(&self, instance: &str) -> LocalHandlerMetrics {
        LocalHandlerMetrics {
            inflight: self.local_handler_inflight.with_label_values(&[instance]),
            duration: self.local_handler_duration.with_label_values(&[instance]),
        }
    }

    pub fn remove_tunnel(&self, server: &str, count: usize) {
        for connection_index in 0..count {
            let connection_index = connection_index.to_string();
            let labels = [server, connection_index.as_str()];

            let _ = self.opened.remove_label_values(&labels);
            let _ = self.draining.remove_label_values(&labels);
            let _ = self.connection_attempts.remove_label_values(&labels);
            let _ = self.requests_inflight.remove_label_values(&[
                server,
                connection_index.as_str(),
                "inbound",
            ]);
        }
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

fn elapsed_seconds(duration: Duration) -> f64 {
    duration.as_secs_f64()
}
