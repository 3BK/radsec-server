use std::collections::HashMap;
use tokio::sync::mpsc;
use tokio::time::{interval, Duration};
use tracing::info;

#[derive(Debug, Clone)]
pub enum MetricSample {
    SessionOpened,
    SessionClosed,
    PacketRx(usize),
    TlsHandshakeMs(u64),
    UpstreamRttMs(u64),
    QueueDrop(&'static str),
    Reject(&'static str),
    StateViolation,
}

pub type MetricsTx = mpsc::Sender<MetricSample>;
pub type MetricsRx = mpsc::Receiver<MetricSample>;

pub fn spawn_metrics_actor(mut rx: MetricsRx, flush_interval_secs: u64) {
    tokio::spawn(async move {
        let mut ticker = interval(Duration::from_secs(flush_interval_secs));

        let mut counters: HashMap<&'static str, u64> = HashMap::new();
        let mut packet_bytes: u64 = 0;
        let mut tls_handshake_ms_total: u128 = 0;
        let mut tls_handshake_count: u64 = 0;
        let mut upstream_rtt_ms_total: u128 = 0;
        let mut upstream_rtt_count: u64 = 0;

        loop {
            tokio::select! {
                Some(sample) = rx.recv() => {
                    match sample {
                        MetricSample::SessionOpened => incr(&mut counters, "sessions_opened"),
                        MetricSample::SessionClosed => incr(&mut counters, "sessions_closed"),
                        MetricSample::PacketRx(n) => {
                            incr(&mut counters, "packets_rx");
                            packet_bytes = packet_bytes.saturating_add(n as u64);
                        }
                        MetricSample::TlsHandshakeMs(v) => {
                            incr(&mut counters, "tls_handshakes");
                            tls_handshake_ms_total += v as u128;
                            tls_handshake_count += 1;
                        }
                        MetricSample::UpstreamRttMs(v) => {
                            incr(&mut counters, "upstream_requests");
                            upstream_rtt_ms_total += v as u128;
                            upstream_rtt_count += 1;
                        }
                        MetricSample::QueueDrop(which) => {
                            incr(&mut counters, which);
                        }
                        MetricSample::Reject(which) => {
                            incr(&mut counters, which);
                            incr(&mut counters, "rejects_total");
                        }
                        MetricSample::StateViolation => {
                            incr(&mut counters, "state_violations");
                        }
                    }
                }
                _ = ticker.tick() => {
                    let tls_avg = if tls_handshake_count > 0 {
                        (tls_handshake_ms_total / tls_handshake_count as u128) as u64
                    } else { 0 };

                    let upstream_avg = if upstream_rtt_count > 0 {
                        (upstream_rtt_ms_total / upstream_rtt_count as u128) as u64
                    } else { 0 };

                    info!(
                        action = "metrology_flush",
                        sessions_opened = counters.get("sessions_opened").copied().unwrap_or(0),
                        sessions_closed = counters.get("sessions_closed").copied().unwrap_or(0),
                        packets_rx = counters.get("packets_rx").copied().unwrap_or(0),
                        packet_bytes = packet_bytes,
                        tls_handshakes = counters.get("tls_handshakes").copied().unwrap_or(0),
                        tls_handshake_avg_ms = tls_avg,
                        upstream_requests = counters.get("upstream_requests").copied().unwrap_or(0),
                        upstream_rtt_avg_ms = upstream_avg,
                        rejects_total = counters.get("rejects_total").copied().unwrap_or(0),
                        queue_drop_control = counters.get("queue_drop_control").copied().unwrap_or(0),
                        queue_drop_shadow = counters.get("queue_drop_shadow").copied().unwrap_or(0),
                        queue_drop_metrics = counters.get("queue_drop_metrics").copied().unwrap_or(0),
                        state_violations = counters.get("state_violations").copied().unwrap_or(0),
                        reject_eap = counters.get("reject_eap").copied().unwrap_or(0),
                        reject_upstream = counters.get("reject_upstream").copied().unwrap_or(0),
                        reject_policy = counters.get("reject_policy").copied().unwrap_or(0),
                        "Edge metrology snapshot"
                    );
                }
            }
        }
    });
}

fn incr(counters: &mut HashMap<&'static str, u64>, key: &'static str) {
    *counters.entry(key).or_insert(0) += 1;
}
