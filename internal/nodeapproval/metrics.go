package nodeapproval

import "github.com/prometheus/client_golang/prometheus"

const metricsNamespace = "privacyproxy"

// Why a lane gave up on approvals (the reason label of approval_dropped_total).
const (
	dropPermanent = "permanent" // the producer refused the batch with a final status
	dropExpired   = "expired"   // expires_at passed before the producer confirmed the batch
	dropEvicted   = "evicted"   // OPS_APPROVAL_RETAIN_MAX removed the batch before the lane sent it
)

// Why Enqueue refused an approval (the reason label of approval_enqueue_refused_total).
const (
	refusedClosed    = "closed"
	refusedNotReady  = "not_ready"
	refusedQueueFull = "queue_full"
)

// deliveryMetrics are the delivery lanes' collectors. Targets come from configuration, so the
// target label is bounded.
type deliveryMetrics struct {
	batches      *prometheus.CounterVec
	retries      *prometheus.CounterVec
	dropped      *prometheus.CounterVec
	redeliveries *prometheus.CounterVec
	mismatches   *prometheus.CounterVec
	inFlight     *prometheus.GaugeVec
	connected    *prometheus.GaugeVec
	latency      *prometheus.HistogramVec
	retained     prometheus.Gauge
	evicted      prometheus.Counter
	refused      *prometheus.CounterVec
}

func newDeliveryMetrics() *deliveryMetrics {
	return &deliveryMetrics{
		batches: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Name:      "approval_batches_total",
			Help:      "Deliver calls by target and gRPC status code; a full store (UNAVAILABLE with ops-approval-reason: store-full) counts as StoreFull.",
		}, []string{"target", "code"}),
		retries: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Name:      "approval_retries_total",
			Help:      "Deliver calls that failed with a retryable status, so their batch waits for another attempt.",
		}, []string{"target"}),
		dropped: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Name:      "approval_dropped_total",
			Help:      "Approvals a producer will not receive from OPS, by target and reason: permanent (refused), expired (not confirmed before expires_at), evicted (removed by the retention cap before it was sent).",
		}, []string{"target", "reason"}),
		redeliveries: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Name:      "approval_redeliveries_total",
			Help:      "Producer restarts noticed through a new boot id, each starting a redelivery of the retained approvals.",
		}, []string{"target"}),
		mismatches: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Name:      "approval_target_mismatches_total",
			Help:      "Status answers whose chain id or trusted key ids do not match what OPS signs, by target and setting.",
		}, []string{"target", "setting"}),
		inFlight: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: metricsNamespace,
			Name:      "approval_calls_in_flight",
			Help:      "Deliver calls in flight per target.",
		}, []string{"target"}),
		connected: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: metricsNamespace,
			Name:      "approval_target_connected",
			Help:      "1 while the connection to the target is ready, else 0.",
		}, []string{"target"}),
		latency: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: metricsNamespace,
			Name:      "approval_delivery_seconds",
			Help:      "Time from signing a batch to the target confirming it stored the batch, retries included.",
			Buckets:   []float64{0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10},
		}, []string{"target"}),
		retained: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: metricsNamespace,
			Name:      "approval_retained",
			Help:      "Approvals OPS retains for redelivery to a producer that restarts.",
		}),
		evicted: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Name:      "approval_evicted_total",
			Help:      "Approvals removed from retention by OPS_APPROVAL_RETAIN_MAX before they expired; a producer restart can no longer get them back.",
		}),
		refused: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Name:      "approval_enqueue_refused_total",
			Help:      "Approvals Enqueue refused, so their transactions were answered 503 and not forwarded, by reason.",
		}, []string{"reason"}),
	}
}

func (m *deliveryMetrics) collectors() []prometheus.Collector {
	return []prometheus.Collector{m.batches, m.retries, m.dropped, m.redeliveries, m.mismatches, m.inFlight,
		m.connected, m.latency, m.retained, m.evicted, m.refused}
}

// Describe and Collect make the Service a prometheus.Collector, registered next to the server's
// own metrics. A preflight-only Service has none.
func (s *Service) Describe(ch chan<- *prometheus.Desc) {
	if s.metrics == nil {
		return
	}
	for _, c := range s.metrics.collectors() {
		c.Describe(ch)
	}
}

func (s *Service) Collect(ch chan<- prometheus.Metric) {
	if s.metrics == nil {
		return
	}
	for _, c := range s.metrics.collectors() {
		c.Collect(ch)
	}
}
