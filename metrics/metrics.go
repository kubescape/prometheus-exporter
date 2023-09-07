package metrics

import (
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	namespaceCritical = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "kubescape_controls_total_namespace_critical",
		Help: "Total number of critical vulnerabilities in the namespace",
	})

	namespaceHigh = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "kubescape_controls_total_namespace_high",
		Help: "Total number of high vulnerabilities in the namespace",
	})

	namespaceMedium = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "kubescape_controls_total_namespace_medium",
		Help: "Total number of medium vulnerabilities in the namespace",
	})

	namespaceLow = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "kubescape_controls_total_namespace_low",
		Help: "Total number of low vulnerabilities in the namespace",
	})

	namespaceUnknown = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "kubescape_controls_total_namespace_unknown",
		Help: "Total number of unknown vulnerabilities in the namespace",
	})
	clusterCritical = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "kubescape_controls_total_cluster_critical",
		Help: "Total number of critical vulnerabilities in the cluster",
	})

	clusterHigh = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "kubescape_controls_total_cluster_high",
		Help: "Total number of high vulnerabilities in the cluster",
	})

	clusterMedium = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "kubescape_controls_total_cluster_medium",
		Help: "Total number of medium vulnerabilities in the cluster",
	})

	clusterLow = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "kubescape_controls_total_cluster_low",
		Help: "Total number of low vulnerabilities in the cluster",
	})

	clusterUnknown = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "kubescape_controls_total_cluster_unknown",
		Help: "Total number of unknown vulnerabilities in the cluster",
	})
)

func init() {
	prometheus.MustRegister(namespaceCritical)
	prometheus.MustRegister(namespaceHigh)
	prometheus.MustRegister(namespaceMedium)
	prometheus.MustRegister(namespaceLow)
	prometheus.MustRegister(namespaceUnknown)
	prometheus.MustRegister(clusterCritical)
	prometheus.MustRegister(clusterHigh)
	prometheus.MustRegister(clusterMedium)
	prometheus.MustRegister(clusterLow)
	prometheus.MustRegister(clusterUnknown)

}

func ProcessNamespaceMetrics(summary *v1beta1.ScopedConfigurationScanSummary) {
	namespaceCritical.Set(float64(summary.Spec.Severities.Critical))
	namespaceHigh.Set(float64(summary.Spec.Severities.High))
	namespaceLow.Set(float64(summary.Spec.Severities.Low))
	namespaceMedium.Set(float64(summary.Spec.Severities.Medium))
	namespaceUnknown.Set(float64(summary.Spec.Severities.Unknown))
}

func ProcessClusterMetrics(summary *v1beta1.ScopedConfigurationScanSummaryList) {

	totalCritical := 0
	totalHigh := 0
	totalLow := 0
	totalMedium := 0
	totalUnknown := 0

	for _, item := range summary.Items {
		totalCritical += item.Spec.Severities.Critical
		totalHigh += item.Spec.Severities.High
		totalMedium += item.Spec.Severities.Medium
		totalLow += item.Spec.Severities.Low
		totalUnknown += item.Spec.Severities.Unknown
	}

	clusterCritical.Set(float64(totalCritical))
	clusterHigh.Set(float64(totalHigh))
	clusterLow.Set(float64(totalLow))
	clusterMedium.Set(float64(totalMedium))
	clusterUnknown.Set(float64(totalUnknown))
}
