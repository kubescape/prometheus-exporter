package metrics

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func metricIsExposed(t *testing.T, sample string) bool {
	t.Helper()
	response := httptest.NewRecorder()
	promhttp.Handler().ServeHTTP(response, httptest.NewRequest("GET", "/metrics", nil))
	if response.Code != 200 {
		t.Fatalf("metrics scrape returned HTTP %d", response.Code)
	}
	return strings.Contains(response.Body.String(), sample)
}

func assertNamespaceSamples(t *testing.T, metricNames []string, namespace string, want bool) {
	t.Helper()
	response := httptest.NewRecorder()
	promhttp.Handler().ServeHTTP(response, httptest.NewRequest("GET", "/metrics", nil))
	if response.Code != 200 {
		t.Fatalf("metrics scrape returned HTTP %d", response.Code)
	}
	for _, name := range metricNames {
		sample := name + `{namespace="` + namespace + `"}`
		if got := strings.Contains(response.Body.String(), sample); got != want {
			t.Errorf("metric %s in namespace %s: exposed=%t, want %t", name, namespace, got, want)
		}
	}
}

func TestNamespaceMetricFamiliesFollowCompleteSnapshots(t *testing.T) {
	configMetrics := []string{
		"kubescape_controls_total_namespace_critical",
		"kubescape_controls_total_namespace_high",
		"kubescape_controls_total_namespace_medium",
		"kubescape_controls_total_namespace_low",
		"kubescape_controls_total_namespace_unknown",
	}
	vulnMetrics := []string{
		"kubescape_vulnerabilities_total_namespace_critical",
		"kubescape_vulnerabilities_total_namespace_high",
		"kubescape_vulnerabilities_total_namespace_medium",
		"kubescape_vulnerabilities_total_namespace_low",
		"kubescape_vulnerabilities_total_namespace_negligible",
		"kubescape_vulnerabilities_total_namespace_unknown",
		"kubescape_vulnerabilities_relevant_namespace_critical",
		"kubescape_vulnerabilities_relevant_namespace_high",
		"kubescape_vulnerabilities_relevant_namespace_medium",
		"kubescape_vulnerabilities_relevant_namespace_low",
		"kubescape_vulnerabilities_relevant_namespace_negligible",
		"kubescape_vulnerabilities_relevant_namespace_unknown",
	}
	configRemoved := v1beta1.ConfigurationScanSummary{ObjectMeta: metav1.ObjectMeta{Name: "audit-config-all-removed"}}
	configRetained := v1beta1.ConfigurationScanSummary{ObjectMeta: metav1.ObjectMeta{Name: "audit-config-all-retained"}}
	vulnRemoved := v1beta1.VulnerabilitySummary{ObjectMeta: metav1.ObjectMeta{Name: "audit-vuln-all-removed"}}
	vulnRetained := v1beta1.VulnerabilitySummary{ObjectMeta: metav1.ObjectMeta{Name: "audit-vuln-all-retained"}}
	ProcessConfigscanNamespaceMetrics(&v1beta1.ConfigurationScanSummaryList{Items: []v1beta1.ConfigurationScanSummary{configRemoved, configRetained}})
	ProcessVulnNamespaceMetrics(&v1beta1.VulnerabilitySummaryList{Items: []v1beta1.VulnerabilitySummary{vulnRemoved, vulnRetained}})
	assertNamespaceSamples(t, configMetrics, configRemoved.Name, true)
	assertNamespaceSamples(t, vulnMetrics, vulnRemoved.Name, true)

	// A nonempty replacement removes only absent namespaces in its own family.
	ProcessConfigscanNamespaceMetrics(&v1beta1.ConfigurationScanSummaryList{Items: []v1beta1.ConfigurationScanSummary{configRetained}})
	ProcessVulnNamespaceMetrics(&v1beta1.VulnerabilitySummaryList{Items: []v1beta1.VulnerabilitySummary{vulnRetained}})
	assertNamespaceSamples(t, configMetrics, configRemoved.Name, false)
	assertNamespaceSamples(t, configMetrics, configRetained.Name, true)
	assertNamespaceSamples(t, vulnMetrics, vulnRemoved.Name, false)
	assertNamespaceSamples(t, vulnMetrics, vulnRetained.Name, true)

	// An empty successful response removes the last namespace, without changing
	// metrics from the other summary endpoint. Reappearing namespaces are restored.
	ProcessConfigscanNamespaceMetrics(&v1beta1.ConfigurationScanSummaryList{})
	assertNamespaceSamples(t, configMetrics, configRetained.Name, false)
	assertNamespaceSamples(t, vulnMetrics, vulnRetained.Name, true)
	ProcessConfigscanNamespaceMetrics(&v1beta1.ConfigurationScanSummaryList{Items: []v1beta1.ConfigurationScanSummary{configRemoved}})
	assertNamespaceSamples(t, configMetrics, configRemoved.Name, true)
	ProcessVulnNamespaceMetrics(&v1beta1.VulnerabilitySummaryList{})
	assertNamespaceSamples(t, vulnMetrics, vulnRetained.Name, false)
	assertNamespaceSamples(t, configMetrics, configRemoved.Name, true)
	ProcessVulnNamespaceMetrics(&v1beta1.VulnerabilitySummaryList{Items: []v1beta1.VulnerabilitySummary{vulnRemoved}})
	assertNamespaceSamples(t, vulnMetrics, vulnRemoved.Name, true)
}

func TestConfigNamespaceMetricsRemoveAbsentNamespace(t *testing.T) {
	first := &v1beta1.ConfigurationScanSummaryList{Items: []v1beta1.ConfigurationScanSummary{
		{ObjectMeta: metav1.ObjectMeta{Name: "audit-config-removed"}, Spec: v1beta1.ConfigurationScanSummarySpec{Severities: v1beta1.WorkloadConfigurationScanSeveritiesSummary{Critical: 7}}},
		{ObjectMeta: metav1.ObjectMeta{Name: "audit-config-retained"}, Spec: v1beta1.ConfigurationScanSummarySpec{Severities: v1beta1.WorkloadConfigurationScanSeveritiesSummary{Critical: 2}}},
	}}
	removed := `kubescape_controls_total_namespace_critical{namespace="audit-config-removed"} 7`
	retained := `kubescape_controls_total_namespace_critical{namespace="audit-config-retained"} 2`
	ProcessConfigscanNamespaceMetrics(first)
	if !metricIsExposed(t, removed) || !metricIsExposed(t, retained) {
		t.Fatal("initial Storage snapshot was not exposed")
	}
	retainedGauge, err := namespaceCritical.GetMetricWithLabelValues("audit-config-retained")
	if err != nil {
		t.Fatal(err)
	}

	updated := first.Items[1]
	updated.Spec.Severities.Critical = 3
	ProcessConfigscanNamespaceMetrics(&v1beta1.ConfigurationScanSummaryList{Items: []v1beta1.ConfigurationScanSummary{updated}})
	if metricIsExposed(t, removed) {
		t.Fatal("removed namespace remains exposed after the next complete Storage snapshot")
	}
	if !metricIsExposed(t, `kubescape_controls_total_namespace_critical{namespace="audit-config-retained"} 3`) {
		t.Fatal("retained namespace did not receive its updated value")
	}
	retainedGaugeAfter, err := namespaceCritical.GetMetricWithLabelValues("audit-config-retained")
	if err != nil {
		t.Fatal(err)
	}
	if retainedGauge != retainedGaugeAfter {
		t.Fatal("retained namespace gauge was deleted and recreated during refresh")
	}
}

func TestVulnerabilityNamespaceMetricsRemoveAbsentNamespace(t *testing.T) {
	first := &v1beta1.VulnerabilitySummaryList{Items: []v1beta1.VulnerabilitySummary{
		{ObjectMeta: metav1.ObjectMeta{Name: "audit-vuln-removed"}, Spec: v1beta1.VulnerabilitySummarySpec{Severities: v1beta1.SeveritySummary{Critical: v1beta1.VulnerabilityCounters{All: 5, Relevant: 3}}}},
		{ObjectMeta: metav1.ObjectMeta{Name: "audit-vuln-retained"}, Spec: v1beta1.VulnerabilitySummarySpec{Severities: v1beta1.SeveritySummary{Critical: v1beta1.VulnerabilityCounters{All: 1, Relevant: 1}}}},
	}}
	removed := `kubescape_vulnerabilities_total_namespace_critical{namespace="audit-vuln-removed"} 5`
	retained := `kubescape_vulnerabilities_total_namespace_critical{namespace="audit-vuln-retained"} 1`
	ProcessVulnNamespaceMetrics(first)
	if !metricIsExposed(t, removed) || !metricIsExposed(t, retained) {
		t.Fatal("initial Storage snapshot was not exposed")
	}
	retainedGauge, err := namespaceVulnCritical.GetMetricWithLabelValues("audit-vuln-retained")
	if err != nil {
		t.Fatal(err)
	}

	updated := first.Items[1]
	updated.Spec.Severities.Critical.All = 2
	ProcessVulnNamespaceMetrics(&v1beta1.VulnerabilitySummaryList{Items: []v1beta1.VulnerabilitySummary{updated}})
	if metricIsExposed(t, removed) {
		t.Fatal("removed namespace remains exposed after the next complete Storage snapshot")
	}
	if !metricIsExposed(t, `kubescape_vulnerabilities_total_namespace_critical{namespace="audit-vuln-retained"} 2`) {
		t.Fatal("retained namespace did not receive its updated value")
	}
	retainedGaugeAfter, err := namespaceVulnCritical.GetMetricWithLabelValues("audit-vuln-retained")
	if err != nil {
		t.Fatal(err)
	}
	if retainedGauge != retainedGaugeAfter {
		t.Fatal("retained namespace gauge was deleted and recreated during refresh")
	}
}
