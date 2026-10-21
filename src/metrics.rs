use prometheus::{
    Encoder, Histogram, HistogramOpts, HistogramVec, IntCounterVec, IntGauge, IntGaugeVec, Opts,
    Registry, TextEncoder,
    core::{AtomicI64, AtomicU64, GenericCounter, GenericGauge},
};
use std::{
    sync::{Arc, LazyLock},
    time::Instant,
};

const REQUEST_DURATION_BUCKETS: &[f64] = &[
    0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0,
];

/// Values of the `status` label on `requests_total`.
const REQUEST_STATUSES: [&str; 2] = ["ok", "error"];

pub struct Metrics {
    registry: Registry,
    opened: IntGaugeVec,
    draining: IntGaugeVec,
    connection_attempts: IntCounterVec,
    requests: IntCounterVec,
    request_duration: HistogramVec,
    requests_inflight: IntGaugeVec,
    local_handler: RequestMetrics,
    local_proxy_requests: IntCounterVec,
    remote_proxy_requests: IntCounterVec,
}

/// Metrics scoped to a particular tunnel server connection
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

    pub fn request_metrics(&self) -> RequestMetrics {
        self.request_metrics.clone()
    }
}

/// Which way a request travels through the tunnel client. Each direction also feeds the
/// legacy `local_proxy_requests_total` / `remote_proxy_requests_total` counters.
#[derive(Clone, Copy)]
enum Direction {
    Inbound,
    Outbound,
}

impl Direction {
    fn label(self) -> &'static str {
        match self {
            Direction::Inbound => "inbound",
            Direction::Outbound => "outbound",
        }
    }
}

/// Counters incremented when a request finishes, one per outcome.
#[derive(Clone)]
struct OutcomeCounters {
    ok: GenericCounter<AtomicU64>,
    error: GenericCounter<AtomicU64>,
    legacy_success: GenericCounter<AtomicU64>,
    legacy_error: GenericCounter<AtomicU64>,
}

struct RequestSeries {
    inflight: GenericGauge<AtomicI64>,
    duration: Histogram,
    outcomes: Option<OutcomeCounters>,
}

/// Pre-resolved series for one (server, connection, direction), so that starting a request
/// involves no label lookups or allocations. Cheap to clone.
#[derive(Clone)]
pub struct RequestMetrics(Arc<RequestSeries>);

impl RequestMetrics {
    pub fn start(&self) -> RequestGuard {
        self.0.inflight.inc();
        RequestGuard {
            metrics: self.clone(),
            start: Instant::now(),
        }
    }
}

/// Tracks one in-flight request. `finish` is the only place an outcome is recorded;
/// dropping the guard without finishing (e.g. a cancelled request) only releases the
/// in-flight slot.
pub struct RequestGuard {
    metrics: RequestMetrics,
    start: Instant,
}

impl RequestGuard {
    pub fn finish(self, success: bool) {
        let series = &self.metrics.0;
        series.duration.observe(self.start.elapsed().as_secs_f64());
        if let Some(outcomes) = &series.outcomes {
            match success {
                true => {
                    outcomes.ok.inc();
                    outcomes.legacy_success.inc();
                }
                false => {
                    outcomes.error.inc();
                    outcomes.legacy_error.inc();
                }
            }
        }
    }
}

impl Drop for RequestGuard {
    fn drop(&mut self) {
        self.metrics.0.inflight.dec();
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

        let local_handler_duration = Histogram::with_opts(
            HistogramOpts::new(
                "local_handler_duration_seconds",
                "Time from forwarding to a local handler until response headers are received",
            )
            .namespace("restate_cloud_tunnel")
            .buckets(REQUEST_DURATION_BUCKETS.to_vec()),
        )
        .expect("metric can be created");
        registry
            .register(Box::new(local_handler_duration.clone()))
            .expect("metric can be registered");

        let local_handler_inflight = IntGauge::with_opts(
            Opts::new(
                "local_handler_inflight",
                "Requests currently waiting on a local handler response",
            )
            .namespace("restate_cloud_tunnel"),
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
            local_handler: RequestMetrics(Arc::new(RequestSeries {
                inflight: local_handler_inflight,
                duration: local_handler_duration,
                outcomes: None,
            })),
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

    /// Create metrics scoped to a particular tunnel server connection
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
            request_metrics: self.request(server, connection_index.as_str(), Direction::Inbound),
        }
    }

    /// Metrics for requests proxied to Restate Cloud. The `connection` label is empty because
    /// the outbound connection pool index is not a tunnel connection.
    pub fn outbound_request(&self, server: &str) -> RequestMetrics {
        self.request(server, "", Direction::Outbound)
    }

    /// Metrics for the time spent waiting on local handlers, across all destinations.
    pub fn local_handler(&self) -> RequestMetrics {
        self.local_handler.clone()
    }

    fn request(&self, server: &str, connection: &str, direction: Direction) -> RequestMetrics {
        let direction_label = direction.label();
        let (legacy_success, legacy_error) = match direction {
            Direction::Inbound => (
                self.local_proxy_requests.with_label_values(&["success"]),
                self.local_proxy_requests.with_label_values(&["error"]),
            ),
            Direction::Outbound => (
                self.remote_proxy_requests.with_label_values(&["success"]),
                self.remote_proxy_requests.with_label_values(&["error"]),
            ),
        };

        RequestMetrics(Arc::new(RequestSeries {
            inflight: self.requests_inflight.with_label_values(&[
                server,
                connection,
                direction_label,
            ]),
            duration: self.request_duration.with_label_values(&[
                server,
                connection,
                direction_label,
            ]),
            outcomes: Some(OutcomeCounters {
                ok: self
                    .requests
                    .with_label_values(&[server, connection, direction_label, "ok"]),
                error: self.requests.with_label_values(&[
                    server,
                    connection,
                    direction_label,
                    "error",
                ]),
                legacy_success,
                legacy_error,
            }),
        }))
    }

    /// Remove every series created by `tunnel` for this server, including inbound request series.
    pub fn remove_tunnel(&self, server: &str, count: usize) {
        for connection_index in 0..count {
            let connection_index = connection_index.to_string();
            let tunnel_labels = [server, connection_index.as_str()];
            let request_labels = [
                server,
                connection_index.as_str(),
                Direction::Inbound.label(),
            ];

            let _ = self.opened.remove_label_values(&tunnel_labels);
            let _ = self.draining.remove_label_values(&tunnel_labels);
            let _ = self.connection_attempts.remove_label_values(&tunnel_labels);
            let _ = self.requests_inflight.remove_label_values(&request_labels);
            let _ = self.request_duration.remove_label_values(&request_labels);
            for status in REQUEST_STATUSES {
                let _ = self.requests.remove_label_values(&[
                    request_labels[0],
                    request_labels[1],
                    request_labels[2],
                    status,
                ]);
            }
        }
    }
}

pub static METRICS: LazyLock<Metrics> = LazyLock::new(Metrics::new);

#[cfg(test)]
mod tests {
    use super::*;

    fn series_count(metrics: &Metrics, server: &str) -> usize {
        metrics
            .render()
            .lines()
            .filter(|line| line.contains(&format!("server=\"{server}\"")))
            .count()
    }

    #[test]
    fn remove_tunnel_removes_every_inbound_series() {
        let metrics = Metrics::new();
        let tunnel = metrics.tunnel("tunnel.test:443", 0);
        tunnel.opened(true);
        tunnel.draining(true);
        tunnel.inc_connection_attempts();
        tunnel.request_metrics().start().finish(true);
        tunnel.request_metrics().start().finish(false);
        assert!(series_count(&metrics, "tunnel.test:443") > 0);

        metrics.remove_tunnel("tunnel.test:443", 1);

        assert_eq!(series_count(&metrics, "tunnel.test:443"), 0);
    }

    #[test]
    fn finish_records_requests_total_and_legacy_counter_once() {
        let metrics = Metrics::new();
        metrics
            .outbound_request("cloud.test:8080")
            .start()
            .finish(false);

        let rendered = metrics.render();
        assert!(rendered.contains(
            "restate_cloud_tunnel_requests_total{connection=\"\",direction=\"outbound\",server=\"cloud.test:8080\",status=\"error\"} 1"
        ));
        assert!(
            rendered
                .contains("restate_cloud_tunnel_remote_proxy_requests_total{status=\"error\"} 1")
        );
        assert!(rendered.contains("restate_cloud_tunnel_requests_inflight{connection=\"\",direction=\"outbound\",server=\"cloud.test:8080\"} 0"));
    }

    #[test]
    fn dropped_guard_releases_inflight_without_recording_outcome() {
        let metrics = Metrics::new();
        let request_metrics = metrics.outbound_request("cloud.test:9070");
        let guard = request_metrics.start();
        drop(guard);

        let rendered = metrics.render();
        assert!(rendered.contains("restate_cloud_tunnel_requests_inflight{connection=\"\",direction=\"outbound\",server=\"cloud.test:9070\"} 0"));
        assert!(rendered.contains("restate_cloud_tunnel_requests_total{connection=\"\",direction=\"outbound\",server=\"cloud.test:9070\",status=\"ok\"} 0"));
    }
}
