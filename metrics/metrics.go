package metrics

import (
	vuln "github.com/kubescape/storage/pkg/apis/softwarecomposition"
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

	namespaceVulnCritical = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "kubescape_vulnerabilities_total_namespace_critical",
		Help: "Total number of critical vulnerabilities in the namespace",
	})

	namespaceVulnHigh = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "kubescape_vulnerabilities_total_namespace_high",
		Help: "Total number of high vulnerabilities in the namespace",
	})

	namespaceVulnMedium = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "kubescape_vulnerabilities_total_namespace_medium",
		Help: "Total number of medium vulnerabilities in the namespace",
	})

	namespaceVulnLow = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "kubescape_vulnerabilities_total_namespace_low",
		Help: "Total number of low vulnerabilities in the namespace",
	})

	namespaceVulnUnknown = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "kubescape_vulnerabilities_total_namespace_unknown",
		Help: "Total number of unknown vulnerabilities in the namespace",
	})
	clusterVulnCritical = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "kubescape_vulnerabilities_total_cluster_critical",
		Help: "Total number of critical vulnerabilities in the cluster",
	})

	clusterVulnHigh = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "kubescape_vulnerabilities_total_cluster_high",
		Help: "Total number of high vulnerabilities in the cluster",
	})

	clusterVulnMedium = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "kubescape_vulnerabilities_total_cluster_medium",
		Help: "Total number of medium vulnerabilities in the cluster",
	})

	clusterVulnLow = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "kubescape_vulnerabilities_total_cluster_low",
		Help: "Total number of low vulnerabilities in the cluster",
	})

	clusterVulnUnknown = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "kubescape_vulnerabilities_total_cluster_unknown",
		Help: "Total number of unknown vulnerabilities in the cluster",
	})

	namespaceVulnCriticalRelevant = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "kubescape_vulnerabilities_relevant_namespace_critical",
		Help: "Number of relevant critical vulnerabilities in the namespace",
	})

	namespaceVulnHighRelevant = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "kubescape_vulnerabilities_relevant_namespace_high",
		Help: "Number of relevant high vulnerabilities in the namespace",
	})

	namespaceVulnMediumRelevant = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "kubescape_vulnerabilities_relevant_namespace_medium",
		Help: "Number of relevant medium vulnerabilities in the namespace",
	})

	namespaceVulnLowRelevant = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "kubescape_vulnerabilities_relevant_namespace_low",
		Help: "Number of relevant low vulnerabilities in the namespace",
	})

	namespaceVulnUnknownRelevant = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "kubescape_vulnerabilities_relevant_namespace_unknown",
		Help: "Number of relevant unknown vulnerabilities in the namespace",
	})


	clusterVulnCriticalRelevant = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "kubescape_vulnerabilities_relevant_cluster_critical",
		Help: "Number of relevant critical vulnerabilities in the cluster",
	})

	clusterVulnHighRelevant = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "kubescape_vulnerabilities_relevant_cluster_high",
		Help: "Number of relevant high vulnerabilities in the cluster",
	})

	clusterVulnMediumRelevant = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "kubescape_vulnerabilities_relevant_cluster_medium",
		Help: "Number of relevant medium vulnerabilities in the cluster",
	})

	clusterVulnLowRelevant = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "kubescape_vulnerabilities_relevant_cluster_low",
		Help: "Number of relevant low vulnerabilities in the cluster",
	})

	clusterVulnUnknownRelevant = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "kubescape_vulnerabilities_relevant_cluster_unknown",
		Help: "Number of relevant unknown vulnerabilities in the cluster",
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
	prometheus.MustRegister(namespaceVulnCritical)
	prometheus.MustRegister(namespaceVulnHigh)
	prometheus.MustRegister(namespaceVulnMedium)
	prometheus.MustRegister(namespaceVulnLow)
	prometheus.MustRegister(namespaceVulnUnknown)
	prometheus.MustRegister(clusterVulnCritical)
	prometheus.MustRegister(clusterVulnHigh)
	prometheus.MustRegister(clusterVulnMedium)
	prometheus.MustRegister(clusterVulnLow)
	prometheus.MustRegister(clusterVulnUnknown)
	prometheus.MustRegister(namespaceVulnCriticalRelevant)
	prometheus.MustRegister(namespaceVulnHighRelevant)
	prometheus.MustRegister(namespaceVulnMediumRelevant)
	prometheus.MustRegister(namespaceVulnLowRelevant)
	prometheus.MustRegister(namespaceVulnUnknownRelevant)
	prometheus.MustRegister(clusterVulnCriticalRelevant)
	prometheus.MustRegister(clusterVulnHighRelevant)
	prometheus.MustRegister(clusterVulnMediumRelevant)
	prometheus.MustRegister(clusterVulnLowRelevant)
	prometheus.MustRegister(clusterVulnUnknownRelevant)
}

func ProcessConfigscanNamespaceMetrics(summary *vuln.ConfigurationScanSummary) {
	namespaceCritical.Set(float64(summary.Spec.Severities.Critical))
	namespaceHigh.Set(float64(summary.Spec.Severities.High))
	namespaceLow.Set(float64(summary.Spec.Severities.Low))
	namespaceMedium.Set(float64(summary.Spec.Severities.Medium))
	namespaceUnknown.Set(float64(summary.Spec.Severities.Unknown))
}

func ProcessConfigscanClusterMetrics(summary *vuln.ConfigurationScanSummaryList) {

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

func ProcessVulnNamespaceMetrics(summary *vuln.VulnerabilitySummary) {
	namespaceVulnCritical.Set(float64(summary.Spec.Severities.Critical.All))
	namespaceVulnHigh.Set(float64(summary.Spec.Severities.High.All))
	namespaceVulnLow.Set(float64(summary.Spec.Severities.Low.All))
	namespaceVulnMedium.Set(float64(summary.Spec.Severities.Medium.All))
	namespaceVulnUnknown.Set(float64(summary.Spec.Severities.Unknown.All))
	namespaceVulnCriticalRelevant.Set(float64(summary.Spec.Severities.Critical.Relevant))
	namespaceVulnHighRelevant.Set(float64(summary.Spec.Severities.High.Relevant))
	namespaceVulnLowRelevant.Set(float64(summary.Spec.Severities.Low.Relevant))
	namespaceVulnMediumRelevant.Set(float64(summary.Spec.Severities.Medium.Relevant))
	namespaceVulnUnknownRelevant.Set(float64(summary.Spec.Severities.Unknown.Relevant))
}

func ProcessVulnClusterMetrics(summary *vuln.VulnerabilitySummaryList) {
	
	totalCritical := 0
	totalHigh := 0
	totalLow := 0
	totalMedium := 0
	totalUnknown := 0

	relevantCritical := 0
	relevantHigh := 0
	relevantLow := 0
	relevantMedium := 0
	relevantUnknown := 0

	for _,item := range summary.Items{
		totalCritical += item.Spec.Severities.Critical.All
		totalHigh += item.Spec.Severities.High.All
		totalMedium += item.Spec.Severities.Medium.All
		totalLow += item.Spec.Severities.Low.All
		totalUnknown += item.Spec.Severities.Unknown.All

		relevantCritical += item.Spec.Severities.Critical.Relevant
		relevantHigh += item.Spec.Severities.High.Relevant
		relevantMedium += item.Spec.Severities.Medium.Relevant
		relevantLow += item.Spec.Severities.Low.Relevant
		relevantUnknown += item.Spec.Severities.Unknown.Relevant


	}
	
	clusterVulnCritical.Set(float64(totalCritical))
	clusterVulnHigh.Set(float64(totalHigh))
	clusterVulnMedium.Set(float64(totalMedium))
	clusterVulnLow.Set(float64(totalLow))
	clusterVulnUnknown.Set(float64(totalUnknown))
	clusterVulnCriticalRelevant.Set(float64(relevantCritical))
	clusterVulnHighRelevant.Set(float64(relevantHigh))
	clusterVulnMediumRelevant.Set(float64(relevantMedium))
	clusterVulnLowRelevant.Set(float64(relevantLow))
	clusterVulnUnknownRelevant.Set(float64(relevantUnknown))
}