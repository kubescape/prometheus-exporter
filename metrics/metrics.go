package metrics

import (
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/prometheus/client_golang/prometheus"
	"strings"
)

var (
	workloadCritical = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "kubescape_controls_total_workload_critical",
		Help: "Total number of critical vulnerabilities in the workload",
	}, []string{"namespace", "workload", "workload_kind"})

	workloadHigh = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "kubescape_controls_total_workload_high",
		Help: "Total number of high vulnerabilities in the workload",
	}, []string{"namespace", "workload", "workload_kind"})

	workloadMedium = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "kubescape_controls_total_workload_medium",
		Help: "Total number of medium vulnerabilities in the workload",
	}, []string{"namespace", "workload", "workload_kind"})

	workloadLow = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "kubescape_controls_total_workload_low",
		Help: "Total number of low vulnerabilities in the workload",
	}, []string{"namespace", "workload", "workload_kind"})

	workloadUnknown = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "kubescape_controls_total_workload_unknown",
		Help: "Total number of unknown vulnerabilities in the workload",
	}, []string{"namespace", "workload", "workload_kind"})

	namespaceCritical = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "kubescape_controls_total_namespace_critical",
		Help: "Total number of critical vulnerabilities in the namespace",
	}, []string{"namespace"})

	namespaceHigh = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "kubescape_controls_total_namespace_high",
		Help: "Total number of high vulnerabilities in the namespace",
	}, []string{"namespace"})

	namespaceMedium = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "kubescape_controls_total_namespace_medium",
		Help: "Total number of medium vulnerabilities in the namespace",
	}, []string{"namespace"})

	namespaceLow = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "kubescape_controls_total_namespace_low",
		Help: "Total number of low vulnerabilities in the namespace",
	}, []string{"namespace"})

	namespaceUnknown = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "kubescape_controls_total_namespace_unknown",
		Help: "Total number of unknown vulnerabilities in the namespace",
	}, []string{"namespace"})
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

	workloadVulnCritical = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "kubescape_vulnerabilities_total_workload_critical",
		Help: "Total number of critical vulnerabilities in the workload",
	}, []string{"namespace", "workload", "workload_kind"})

	workloadVulnHigh = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "kubescape_vulnerabilities_total_workload_high",
		Help: "Total number of high vulnerabilities in the workload",
	}, []string{"namespace", "workload", "workload_kind"})

	workloadVulnMedium = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "kubescape_vulnerabilities_total_workload_medium",
		Help: "Total number of medium vulnerabilities in the workload",
	}, []string{"namespace", "workload", "workload_kind"})

	workloadVulnLow = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "kubescape_vulnerabilities_total_workload_low",
		Help: "Total number of low vulnerabilities in the workload",
	}, []string{"namespace", "workload", "workload_kind"})

	workloadVulnUnknown = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "kubescape_vulnerabilities_total_workload_unknown",
		Help: "Total number of unknown vulnerabilities in the workload",
	}, []string{"namespace", "workload", "workload_kind"})

	namespaceVulnCritical = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "kubescape_vulnerabilities_total_namespace_critical",
		Help: "Total number of critical vulnerabilities in the namespace",
	}, []string{"namespace"})

	namespaceVulnHigh = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "kubescape_vulnerabilities_total_namespace_high",
		Help: "Total number of high vulnerabilities in the namespace",
	}, []string{"namespace"})

	namespaceVulnMedium = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "kubescape_vulnerabilities_total_namespace_medium",
		Help: "Total number of medium vulnerabilities in the namespace",
	}, []string{"namespace"})

	namespaceVulnLow = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "kubescape_vulnerabilities_total_namespace_low",
		Help: "Total number of low vulnerabilities in the namespace",
	}, []string{"namespace"})

	namespaceVulnUnknown = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "kubescape_vulnerabilities_total_namespace_unknown",
		Help: "Total number of unknown vulnerabilities in the namespace",
	}, []string{"namespace"})
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

	workloadVulnCriticalRelevant = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "kubescape_vulnerabilities_relevant_workload_critical",
		Help: "Number of relevant critical vulnerabilities in the workload",
	}, []string{"namespace", "workload", "workload_kind"})

	workloadVulnHighRelevant = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "kubescape_vulnerabilities_relevant_workload_high",
		Help: "Number of relevant high vulnerabilities in the workload",
	}, []string{"namespace", "workload", "workload_kind"})

	workloadVulnMediumRelevant = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "kubescape_vulnerabilities_relevant_workload_medium",
		Help: "Number of relevant medium vulnerabilities in the workload",
	}, []string{"namespace", "workload", "workload_kind"})

	workloadVulnLowRelevant = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "kubescape_vulnerabilities_relevant_workload_low",
		Help: "Number of relevant low vulnerabilities in the workload",
	}, []string{"namespace", "workload", "workload_kind"})

	workloadVulnUnknownRelevant = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "kubescape_vulnerabilities_relevant_workload_unknown",
		Help: "Number of relevant unknown vulnerabilities in the workload",
	}, []string{"namespace", "workload", "workload_kind"})

	namespaceVulnCriticalRelevant = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "kubescape_vulnerabilities_relevant_namespace_critical",
		Help: "Number of relevant critical vulnerabilities in the namespace",
	}, []string{"namespace"})

	namespaceVulnHighRelevant = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "kubescape_vulnerabilities_relevant_namespace_high",
		Help: "Number of relevant high vulnerabilities in the namespace",
	}, []string{"namespace"})

	namespaceVulnMediumRelevant = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "kubescape_vulnerabilities_relevant_namespace_medium",
		Help: "Number of relevant medium vulnerabilities in the namespace",
	}, []string{"namespace"})

	namespaceVulnLowRelevant = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "kubescape_vulnerabilities_relevant_namespace_low",
		Help: "Number of relevant low vulnerabilities in the namespace",
	}, []string{"namespace"})

	namespaceVulnUnknownRelevant = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "kubescape_vulnerabilities_relevant_namespace_unknown",
		Help: "Number of relevant unknown vulnerabilities in the namespace",
	}, []string{"namespace"})

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
	// TODO check if workload metrics should be enabled by default or if they should be enabled by an env variable
	prometheus.MustRegister(workloadCritical)
	prometheus.MustRegister(workloadHigh)
	prometheus.MustRegister(workloadMedium)
	prometheus.MustRegister(workloadLow)
	prometheus.MustRegister(workloadUnknown)
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
	// TODO check if workload metrics should be enabled by default or if they should be enabled by an env variable
	prometheus.MustRegister(workloadVulnCritical)
	prometheus.MustRegister(workloadVulnHigh)
	prometheus.MustRegister(workloadVulnMedium)
	prometheus.MustRegister(workloadVulnLow)
	prometheus.MustRegister(workloadVulnUnknown)
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
	// TODO check if workload metrics should be enabled by default or if they should be enabled by an env variable
	prometheus.MustRegister(workloadVulnCriticalRelevant)
	prometheus.MustRegister(workloadVulnHighRelevant)
	prometheus.MustRegister(workloadVulnMediumRelevant)
	prometheus.MustRegister(workloadVulnLowRelevant)
	prometheus.MustRegister(workloadVulnUnknownRelevant)
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

func ProcessConfigscanWorkloadMetrics(summary *v1beta1.WorkloadConfigurationScanSummaryList) {
	for _, item := range summary.Items {
		namespace := item.ObjectMeta.Labels["kubescape.io/workload-namespace"]
		workload := item.ObjectMeta.Labels["kubescape.io/workload-name"]
		kind := strings.ToLower(item.ObjectMeta.Labels["kubescape.io/workload-kind"])
		workloadCritical.WithLabelValues(namespace, workload, kind).Set(float64(item.Spec.Severities.Critical))
		workloadHigh.WithLabelValues(namespace, workload, kind).Set(float64(item.Spec.Severities.High))
		workloadLow.WithLabelValues(namespace, workload, kind).Set(float64(item.Spec.Severities.Low))
		workloadMedium.WithLabelValues(namespace, workload, kind).Set(float64(item.Spec.Severities.Medium))
		workloadUnknown.WithLabelValues(namespace, workload, kind).Set(float64(item.Spec.Severities.Unknown))
	}
}

func ProcessConfigscanNamespaceMetrics(summary *v1beta1.ConfigurationScanSummaryList) {
	for _, item := range summary.Items {
		namespace := item.ObjectMeta.Name
		namespaceCritical.WithLabelValues(namespace).Set(float64(item.Spec.Severities.Critical))
		namespaceHigh.WithLabelValues(namespace).Set(float64(item.Spec.Severities.High))
		namespaceLow.WithLabelValues(namespace).Set(float64(item.Spec.Severities.Low))
		namespaceMedium.WithLabelValues(namespace).Set(float64(item.Spec.Severities.Medium))
		namespaceUnknown.WithLabelValues(namespace).Set(float64(item.Spec.Severities.Unknown))
	}
}

func ProcessConfigscanClusterMetrics(summary *v1beta1.ConfigurationScanSummaryList) (totalCritical int, totalHigh int, totalLow int, totalMedium int, totalUnknown int) {

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

	return totalCritical, totalHigh, totalMedium, totalLow, totalUnknown
}

func ProcessVulnWorkloadMetrics(summary *v1beta1.VulnerabilityManifestSummaryList) {
	for _, item := range summary.Items {
		namespace := item.ObjectMeta.Labels["kubescape.io/workload-namespace"]
		workload := item.ObjectMeta.Labels["kubescape.io/workload-name"]
		kind := strings.ToLower(item.ObjectMeta.Labels["kubescape.io/workload-kind"])
		workloadVulnCritical.WithLabelValues(namespace, workload, kind).Set(float64(item.Spec.Severities.Critical.All))
		workloadVulnHigh.WithLabelValues(namespace, workload, kind).Set(float64(item.Spec.Severities.High.All))
		workloadVulnLow.WithLabelValues(namespace, workload, kind).Set(float64(item.Spec.Severities.Low.All))
		workloadVulnMedium.WithLabelValues(namespace, workload, kind).Set(float64(item.Spec.Severities.Medium.All))
		workloadVulnUnknown.WithLabelValues(namespace, workload, kind).Set(float64(item.Spec.Severities.Unknown.All))
		workloadVulnCriticalRelevant.WithLabelValues(namespace, workload, kind).Set(float64(item.Spec.Severities.Critical.Relevant))
		workloadVulnHighRelevant.WithLabelValues(namespace, workload, kind).Set(float64(item.Spec.Severities.High.Relevant))
		workloadVulnLowRelevant.WithLabelValues(namespace, workload, kind).Set(float64(item.Spec.Severities.Low.Relevant))
		workloadVulnMediumRelevant.WithLabelValues(namespace, workload, kind).Set(float64(item.Spec.Severities.Medium.Relevant))
		workloadVulnUnknownRelevant.WithLabelValues(namespace, workload, kind).Set(float64(item.Spec.Severities.Unknown.Relevant))
	}
}

func ProcessVulnNamespaceMetrics(summary *v1beta1.VulnerabilitySummaryList) {
	for _, item := range summary.Items {
		namespace := item.ObjectMeta.Name
		namespaceVulnCritical.WithLabelValues(namespace).Set(float64(item.Spec.Severities.Critical.All))
		namespaceVulnHigh.WithLabelValues(namespace).Set(float64(item.Spec.Severities.High.All))
		namespaceVulnLow.WithLabelValues(namespace).Set(float64(item.Spec.Severities.Low.All))
		namespaceVulnMedium.WithLabelValues(namespace).Set(float64(item.Spec.Severities.Medium.All))
		namespaceVulnUnknown.WithLabelValues(namespace).Set(float64(item.Spec.Severities.Unknown.All))
		namespaceVulnCriticalRelevant.WithLabelValues(namespace).Set(float64(item.Spec.Severities.Critical.Relevant))
		namespaceVulnHighRelevant.WithLabelValues(namespace).Set(float64(item.Spec.Severities.High.Relevant))
		namespaceVulnLowRelevant.WithLabelValues(namespace).Set(float64(item.Spec.Severities.Low.Relevant))
		namespaceVulnMediumRelevant.WithLabelValues(namespace).Set(float64(item.Spec.Severities.Medium.Relevant))
		namespaceVulnUnknownRelevant.WithLabelValues(namespace).Set(float64(item.Spec.Severities.Unknown.Relevant))
	}
}

func ProcessVulnClusterMetrics(summary *v1beta1.VulnerabilitySummaryList) (totalCritical int, totalHigh int, totalLow int, totalMedium int, totalUnknown int, relevantCritical int, relevantHigh int, relevantLow int, relevantMedium int, relevantUnknown int) {

	for _, item := range summary.Items {
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

	return totalCritical, totalHigh, totalMedium, totalLow, totalUnknown, relevantCritical, relevantHigh, relevantMedium, relevantLow, relevantUnknown
}
