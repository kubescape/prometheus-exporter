package collect

import (
	v1beta1 "github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/prometheus/client_golang/prometheus"
	"gopkg.in/yaml.v2"
)

var (
	clusterCritical = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "kubescape_vulnerabilities_total_cluster_critical",
		Help: "Total number of critical vulnerabilities in the cluster",
	})

	clusterHigh = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "kubescape_vulnerabilities_total_cluster_high",
		Help: "Total number of high vulnerabilities in the cluster",
	})

	clusterMedium = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "kubescape_vulnerabilities_total_cluster_medium",
		Help: "Total number of medium vulnerabilities in the cluster",
	})

	clusterLow = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "kubescape_vulnerabilities_total_cluster_low",
		Help: "Total number of low vulnerabilities in the cluster",
	})

	clusterUnknown = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "kubescape_vulnerabilities_total_cluster_unknown",
		Help: "Total number of unknown vulnerabilities in the cluster",
	})
)

func init() {
	prometheus.MustRegister(clusterCritical)
	prometheus.MustRegister(clusterHigh)
	prometheus.MustRegister(clusterMedium)
	prometheus.MustRegister(clusterLow)
	prometheus.MustRegister(clusterUnknown)
}

func GetSeverityValues(yamlData []byte) (*v1beta1.WorkloadConfigurationScanSummary, error) {
	var summary v1beta1.WorkloadConfigurationScanSummary 
	if err := yaml.Unmarshal(yamlData, &summary); err != nil {
		return nil, err
	}
	return &summary, nil
}

func ProcessMetrics(summary *v1beta1.WorkloadConfigurationScanSummary) {
	clusterCritical.Set(float64(summary.Spec.Severities.Critical))
	clusterHigh.Set(float64(summary.Spec.Severities.High))
	clusterMedium.Set(float64(summary.Spec.Severities.Low))
	clusterLow.Set(float64(summary.Spec.Severities.Medium))
	clusterUnknown.Set(float64(summary.Spec.Severities.Unknown))
}
