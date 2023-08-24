package collect

import (
	"fmt"

	"github.com/prometheus/client_golang/prometheus"
	"gopkg.in/yaml.v2"
)

type Severities struct {
	Critical   Severity `yaml:"critical"`
	High       Severity `yaml:"high"`
	Low        Severity `yaml:"low"`
	Medium     Severity `yaml:"medium"`
	Negligible Severity `yaml:"negligible"`
	Unknown    Severity `yaml:"unknown"`
}

type Severity struct {
	All      int `yaml:"all"`
	Relevant int `yaml:"relevant"`
}
type Spec struct {
	Severities Severities `yaml:"severities"`
}
type VulnerabilitySummary struct {
	Spec Spec `yaml:"spec"`
}

var (
	kubescape_vulnerabilities_total_cluster_critical = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "kubescape_vulnerabilities_total_cluster_critical",
		Help: "Total number of critical vulnerabilities in the cluster",
	}, []string{"relevant"})
	kubescape_vulnerabilities_total_cluster_high = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "kubescape_vulnerabilities_total_cluster_high",
		Help: "Total number of high vulnerabilities in the cluster",
	}, []string{"relevant"})
	kubescape_vulnerabilities_total_cluster_medium = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "kubescape_vulnerabilities_total_cluster_medium",
		Help: "Total number of medium vulnerabilities in the cluster",
	}, []string{"relevant"})
	kubescape_vulnerabilities_total_cluster_low = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "kubescape_vulnerabilities_total_cluster_low",
		Help: "Total number of low vulnerabilities in the cluster",
	}, []string{"relevant"})
	kubescape_vulnerabilities_total_cluster_negligible = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "kubescape_vulnerabilities_total_cluster_negligible",
		Help: "Total number of negligible vulnerabilities in the cluster",
	}, []string{"relevant"})
	kubescape_vulnerabilities_total_cluster_unknown = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "kubescape_vulnerabilities_total_cluster_unknown",
		Help: "Total number of unknown vulnerabilities in the cluster",
	}, []string{"relevant"})
)

func init() {
	prometheus.MustRegister(kubescape_vulnerabilities_total_cluster_critical)
	prometheus.MustRegister(kubescape_vulnerabilities_total_cluster_high)
	prometheus.MustRegister(kubescape_vulnerabilities_total_cluster_medium)
	prometheus.MustRegister(kubescape_vulnerabilities_total_cluster_low)
	prometheus.MustRegister(kubescape_vulnerabilities_total_cluster_negligible)
	prometheus.MustRegister(kubescape_vulnerabilities_total_cluster_unknown)

}

func GetSeverityValues(yamlData []byte, severity string) (int, int, error) {
	var summary VulnerabilitySummary
	if err := yaml.Unmarshal(yamlData, &summary); err != nil {
		return 0, 0, err
	}

	switch severity {
	case "critical":
		return summary.Spec.Severities.Critical.All, summary.Spec.Severities.Critical.Relevant, nil
	case "high":
		return summary.Spec.Severities.High.All, summary.Spec.Severities.High.Relevant, nil
	case "low":
		return summary.Spec.Severities.Low.All, summary.Spec.Severities.Low.Relevant, nil
	case "medium":
		return summary.Spec.Severities.Medium.All, summary.Spec.Severities.Medium.Relevant, nil
	case "negligible":
		return summary.Spec.Severities.Negligible.All, summary.Spec.Severities.Negligible.Relevant, nil
	default:
		return 0, 0, fmt.Errorf("unknown severity: %s", severity)
	}
}
