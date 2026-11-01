package metrics

import (
	"bytes"
	"os"
	"testing"

	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/expfmt"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Keep the existing exposition contract pinned before replacing the collector.
func TestSummaryMetricsMatchBaseline(t *testing.T) {
	const namespace = "schema-fixture"
	labels := map[string]string{
		"kubescape.io/workload-namespace":      namespace,
		"kubescape.io/workload-name":           "api",
		"kubescape.io/workload-kind":           "Deployment",
		"kubescape.io/workload-container-name": "App",
	}
	config := v1beta1.WorkloadConfigurationScanSeveritiesSummary{Critical: 1, High: 2, Medium: 3, Low: 4, Unknown: 5}
	vuln := v1beta1.SeveritySummary{
		Critical:   v1beta1.VulnerabilityCounters{All: 6, Relevant: 1},
		High:       v1beta1.VulnerabilityCounters{All: 7, Relevant: 2},
		Medium:     v1beta1.VulnerabilityCounters{All: 8, Relevant: 3},
		Low:        v1beta1.VulnerabilityCounters{All: 9, Relevant: 4},
		Negligible: v1beta1.VulnerabilityCounters{All: 10, Relevant: 5},
		Unknown:    v1beta1.VulnerabilityCounters{All: 11, Relevant: 6},
	}
	configList := &v1beta1.ConfigurationScanSummaryList{Items: []v1beta1.ConfigurationScanSummary{{
		ObjectMeta: metav1.ObjectMeta{Name: namespace}, Spec: v1beta1.ConfigurationScanSummarySpec{Severities: config},
	}}}
	vulnList := &v1beta1.VulnerabilitySummaryList{Items: []v1beta1.VulnerabilitySummary{{
		ObjectMeta: metav1.ObjectMeta{Name: namespace}, Spec: v1beta1.VulnerabilitySummarySpec{Severities: vuln},
	}}}
	workloadConfig := v1beta1.WorkloadConfigurationScanSummary{ObjectMeta: metav1.ObjectMeta{Labels: labels}, Spec: v1beta1.WorkloadConfigurationScanSummarySpec{Severities: config}}
	workloadVuln := v1beta1.VulnerabilityManifestSummary{ObjectMeta: metav1.ObjectMeta{Labels: labels}, Spec: v1beta1.VulnerabilityManifestSummarySpec{Severities: vuln}}
	t.Cleanup(func() {
		DeleteConfigscanWorkloadMetric(&workloadConfig)
		DeleteVulnWorkloadMetric(&workloadVuln)
		ProcessConfigscanNamespaceMetrics(&v1beta1.ConfigurationScanSummaryList{})
		ProcessVulnNamespaceMetrics(&v1beta1.VulnerabilitySummaryList{})
	})
	ProcessConfigscanClusterMetrics(configList)
	ProcessConfigscanNamespaceMetrics(configList)
	ProcessVulnClusterMetrics(vulnList)
	ProcessVulnNamespaceMetrics(vulnList)
	ProcessConfigscanWorkloadMetrics(&v1beta1.WorkloadConfigurationScanSummaryList{Items: []v1beta1.WorkloadConfigurationScanSummary{workloadConfig}})
	ProcessVulnWorkloadMetrics(&v1beta1.VulnerabilityManifestSummaryList{Items: []v1beta1.VulnerabilityManifestSummary{workloadVuln}})

	reg := prometheus.NewRegistry()
	for _, collector := range []prometheus.Collector{
		workloadCritical,
		workloadHigh,
		workloadMedium,
		workloadLow,
		workloadUnknown,
		namespaceCritical,
		namespaceHigh,
		namespaceMedium,
		namespaceLow,
		namespaceUnknown,
		clusterCritical,
		clusterHigh,
		clusterMedium,
		clusterLow,
		clusterUnknown,
		workloadVulnCritical,
		workloadVulnHigh,
		workloadVulnMedium,
		workloadVulnLow,
		workloadVulnNegligible,
		workloadVulnUnknown,
		namespaceVulnCritical,
		namespaceVulnHigh,
		namespaceVulnMedium,
		namespaceVulnLow,
		namespaceVulnNegligible,
		namespaceVulnUnknown,
		clusterVulnCritical,
		clusterVulnHigh,
		clusterVulnMedium,
		clusterVulnLow,
		clusterVulnNegligible,
		clusterVulnUnknown,
		workloadVulnCriticalRelevant,
		workloadVulnHighRelevant,
		workloadVulnMediumRelevant,
		workloadVulnLowRelevant,
		workloadVulnNegligibleRelevant,
		workloadVulnUnknownRelevant,
		namespaceVulnCriticalRelevant,
		namespaceVulnHighRelevant,
		namespaceVulnMediumRelevant,
		namespaceVulnLowRelevant,
		namespaceVulnNegligibleRelevant,
		namespaceVulnUnknownRelevant,
		clusterVulnCriticalRelevant,
		clusterVulnHighRelevant,
		clusterVulnMediumRelevant,
		clusterVulnLowRelevant,
		clusterVulnNegligibleRelevant,
		clusterVulnUnknownRelevant,
	} {
		reg.MustRegister(collector)
	}
	families, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	var got bytes.Buffer
	for _, family := range families {
		// Other tests share the package's gauges. Ignore their label tuples while
		// retaining every descriptor and the cluster totals from this fixture.
		selected := family.Metric[:0]
		for _, sample := range family.Metric {
			include := true
			for _, label := range sample.Label {
				if label.GetName() == "namespace" && label.GetValue() != namespace {
					include = false
				}
			}
			if include {
				selected = append(selected, sample)
			}
		}
		family.Metric = selected
		if _, err := expfmt.MetricFamilyToText(&got, family); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile("testdata/summary_metrics.prom")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Bytes(), want) {
		t.Fatalf("summary metric contract changed\nwant:\n%s\ngot:\n%s", want, got.Bytes())
	}
}
